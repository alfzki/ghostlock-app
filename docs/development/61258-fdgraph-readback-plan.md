# `fd_graph` kernel-readback 実験计划（L 级，待评审）

**状态：待用户评审。评审通过前不得改动攻击关键路径代码。**

依据：`fd-graph-primitive-scoping.md`（§2.9/§2.12/§2.17.1/§2.18.2/§2.19.1）、
门禁 `-05`–`-10`、OQ1 探针结论（管道/epoll 上 `pread` 必 `ESPIPE`；
`/sys/fs/selinux/enforce` shell 可读）。

## 1. 关键澄清：staging 读回不是内核信号

`slot_data[0x166]` 与 GENMARK0 首 8 字节都读自**用户态** 64 KiB staging。
staging 今日只被我们自己的 `memset`/喷洒写入——内核从未碰过它。
因此任何“把 `0x42` 改成 bit4 置位值”的做法都是**自证预言**：
读回恒命中，与内核状态无关，**不得作为成功判据**（若合入即为虚假 PASS，
违反 `RACE_SUMMARY` 口径）。同理 GENMARK0 首槽读回恒不变是**预期内**的，
不是“回收未生效”的证据——它本来就不在内核路径上。

结论：**在 inject 落地之前，不存在诚实可用的人均 round 内核信号。**
本批不伪造信号；只做两件事——（a）用只读内核分配器计数证明我们的操作
真实改变了内核状态（机制反馈，非成功判据）；（b）把该结论钉死，
验收继续走 enforce 文件。

## 2. 实验内容（单变量：只加只读观测，不加任何内核写面）

E1（实施）：`/proc/buddyinfo` 空闲页总数快照。`GRAPH_READY` 后取 A，
expand 全完成后取 B，记 `free_before/free_after/delta`。
预期：大幅负 delta（24k epoll + 240 管道×2 级 + 150 fork 的正常消耗），
证明观测通道活着；delta 的符号/量级**不作任何成功解读**。
文件不可读则记 `unavailable` 并继续（优雅降级）。

E2（不实施，记此存档）：pipe loopback parity（写后读回比对）。
`write` 全长统计已证明 fd 健康；loopback 恒匹配，零内核信息量，
还会扰动后续轮次的管缓冲状态。明确放弃。

## 3. 所有权与生命周期

零新增：栈上 8 KiB 读缓冲（函数作用域内），无新全局/成员/线程/fork。
`open/read/close` 成对出现于同一作用域；失败路径只记 `unavailable`。

## 4. 验证矩阵

| 步骤 | 命令 / 动作 | 预期 |
|---|---|---|
| host | `make -C src native-host-tests` | 全过；新增 `read_buddy_free_total` 向量（罐装 buddyinfo 求和 == 5555、缺失文件 → -1、空文件 → 0；真 `/proc/buddyinfo` 只作存在性宽容断言） |
| build | NDK 构建 | 零警告 |
| lint | `make -C src lint-tidy` | 0 findings（`%ld` 配 `long`；`size_t` 比较显式转换） |
| 反汇编 | `python3 tools/cmp_disasm.py <基线> build/native/ghostlock` | 8 函数 `IDENTICAL` 或已注解 `LAYOUT-SHIFT`；新增 `SHAPE` 即停并反汇编核查 |
| 门禁 | 冷启动 + `tools/gate_preflight.py` 6/6 + 单 route + 固定 CPU 对 + KernelSU 未加载 | `buddy` 行出现且 delta 为大幅负值；其余行与 -10 同形；`chain 0` 诚实；无 panic；自主退出；成败同等归档 |

## 5. 风险与停止条件

- 本批**零新增内核写面**（只有 `/proc` 只读 + 日志），panic 风险面与 -10 相同。
- 若门禁 panic：按 `KERNEL-PANIC-01` 同构建复现 + 冷机复跑；单次只记录。
- `cmp_disasm` 新增 `SHAPE-DIFF` → 停并调查（gate-08 先例：逐条核对 fall-through 与未触及逻辑）。
- 本批之后：per-round 内核信号问题**结案**（不可用）；剩余工作只剩喷洒页→释放环重占时序（OQ2）与触发变体——那是下一个独立 L 级设计，不在本批叠加。

## 6. 评审要点（请确认）

1. “staging 自读回不得作为信号；`bit4` 构造只许出现在未来真实喷洒页里，不许动 staging 哨兵字节”——是否接受该红线？
2. E2 明确放弃（loopback 零信息量 + 扰动循环），是否同意？
3. buddy 快照 A/B 点位（GRAPH_READY 后 / expand 后）是否合适？
