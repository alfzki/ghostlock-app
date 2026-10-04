# `fd_graph` 投递检测批实施计划（L 级，待评审）

**状态：待用户评审。评审通过前不得改动攻击关键路径代码。**

依据：`docs/analysis/fd-graph-primitive-scoping.md`（§2.7/§2.9–§2.12、§2.16–§2.19）、门禁 `-05`/`-06`/`-07`、
`decompiled/annotated.c`（`worker_pool` / `redirect` / `wait_child` / RACE 环）。
父计划：`docs/development/61258-fdgraph-primitive-plan.md`（批次 D，取证已关闭）。

## 1. 目标与非目标

**目标**：把 `chain_hit` 从诚实零值变为真实信号，完成 W1（SELinux permissive），
再 W2/W3 打通 vivo X300 Pro（`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`）整链。

**非目标**：`select_stack` / `tcp_zerocopy` 回退（已证不可行）；`pipe_worker`
独立线程（参考实现是 race 环内同步调用，见 §3.1）；`pread64` 强上（管道返回
`ESPIPE`，见 OQ1）；profile / wire 格式变更（16 字段已齐）；KernelSU 模块加载。

## 2. 已完成的地基（本批不重做，只回归）

| 项 | 证据 |
|---|---|
| W1 PI 窗口 `ret=1` 稳定 | 门禁 -05（2/2 冷启动） |
| 星形 epoll 图 `GRAPH_READY 96/256/24576`，无 `ELOOP` | 门禁 -06（`annotated.c:5255` 勘误：每宽基址 + 256 星形子节点，深度恒 1） |
| 进程自主退出（exit `124` 消除，13/13 `route_done`+join） | 门禁 -07 |
| `write()` 240/240 ×130 轮零短写，`zero_byte_redirect` 模式映射 | 门禁 -07 |
| `BulkFdOwner`、`FdGraphLayout` 16 字段双侧同步 | host 21 suites / lint 0 / `cmp_disasm` 自比较 PASS |
| `GENMARK0 = 0x304b52414d4e4547` | 门禁 -07 日志确认 |

当前树：`99a326d` + 未提交工作树，二进制 `ce448666f063bdcb`（设备侧一致）。

## 3. 本批范围（相对 `ce448666` 的增量）

### D1：reclaim 注水点（spray/inject 落位）

现状缺口：`reclaim_small → reclaim_expand` 背靠背，中间没有任何页喷洒；
`GENMARK` 只写用户态 staging，从未进入内核环。参考顺序（scoping §2.16）：
建图 → 回收 → 建表 → 植毒 → **喷入** → 触发 → 校验；`worker_pool`
逐槽 `F_SETPIPE_SZ`（`annotated.c:4826`）表明缩放是逐槽驱动的，不是两大批。

改动（`FdGraphRoute::execute()` 内，顺序硬约束）：
1. 建管（240 根，fd 回槽，空槽 `-1`）——已有，保持。
2. 逐槽循环：`reclaim_small`（8 KiB + `F_GETPIPE_SZ` 回读）→ **页喷洒**
  （kernelsnitch 碰撞页 + `prepare_kernel_page` 等价物，复用既有 `heap.current`
   路径）→ `reclaim_expand`（128 KiB + 回读）。失败即整轮放弃（参考 `resize_fail`
   致命语义；本批内定为放弃本轮不退出进程，见 §5 风险）。
3. `GENMARK0` 68 份 + `fake_fllink = base | 0x108` 保持，但喷洒目标改为
   expand 后的环槽（OQ2 实验定具体槽位）。

验收：`resize_sample` 双阶段 ×240 零 `resize_fail`（门禁 -07 已有，保持）；
`PIPE_TARGET` 日志行与 profile `objects_per_order3`/`pipe_object`/`pipe_flags` 一致。

### D2：`'W'` 命令门 + 投递确认（不 fork 先行）

参考：worker `read 1 字节 == 'W'` 才写；`redirect` 由子进程投递、父进程
`waitpid` 240 s 超时回收 `rc`（`annotated.c:2694`）。本批先做**单线程版**
（OQ3 实验：若 `chain_hit` 持续为 0 再加 fork；fork 模型用既有 `ChildProcess`，
其 `release_to_handoff()` 语义正好匹配）。

改动：
1. 投递前从控制管读 1 字节命令字，非 `'W'` 则放弃本轮并记日志（与参考同形）。
2. 240 路 `write(drain_fds[i], &value, 8)` 全长校验（已有，D1 后保留）。
3. 回读：**先只做 OQ1 实验**（见 §4），`pread64` 上管道必 `ESPIPE`，
   不得把 `ESPIPE` 当命中；`PIPE_OBSERVED` 只记真实读回。
4. 判据（已有 helper，直接沿用）：`zero_byte_redirect`（W1 Zero 模式）
   `chain_hit` 即成功；他模式 `chain_hit && bit4`。

### D3：验收判据切换到可观测后果

`redirect` 成功后读 `/sys/fs/selinux/enforce`，首字节 `!= '1'` 即 W1 成功，
失败重试一次（scoping §2.17.1）。替换“自读回即成功”的任何写法。
批次 B 的 4 个哨兵保留作诊断，不作判据。

### D4：重试环（已有，行为不变，只补边界）

`delay_us` 阶梯 `{0,1,2,4,8,12,20,32,48,64}` 自 0 递增；成功可在第 0 轮；
`chain_hit==1` 单独在 `pipe_flags` 模式下**不算成功**；短写放弃本轮。
`marker_changed`（`epitem.generation != GENMARK0`）记入 `RACE` 行作诊断。

## 4. 未决问题与最便宜的决定性实验（按依赖排序）

| # | 问题 | 实验（均为只读/低风险优先） | 阻塞 |
|---|---|---|---|
| OQ1 | `pread64` 到底读哪个 fd？管道回 `ESPIPE` | **已回答（2026-10-04 探针 `b875a5bf`）**：reclaim 读端 / drain 写端 / epoll fd 的 `pread` 全部 `-1`/`ESPIPE(29)`；`/sys/fs/selinux/enforce` 以 shell 身份可 `open`+`pread`（回 `1`/`'1'`，`errno 0`）。结论：D2 不得对管道/epoll 用 `pread`；D3 的 enforce-file 验收可行。探针块已移除，树已验证回到 `ce448666`。日志：`logs/gate-20261004-oq1/native.log` | D2-3 |
| OQ2 | 16 项表喷洒与 expand 的交错点 | 非门禁对照：A=现状背靠背，B=small→喷→expand，看 `resize_sample`/`RACE` 行差异与是否 panic；任一 panic 即停（`KERNEL-PANIC-01` 需同构建复现才归因） | D1 |
| OQ3 | fork 是否必需 | 先单线程版上一轮门禁；`chain` 持续 0 才加 `ChildProcess` fork 版 | D2 实现分支 |
| OQ4 | `0x166` 槽位归属 | `PIPE_OBSERVED` 附带 256 B 槽 hex 倾印一次，离线对 `pipe_buffer` 布局（`flags@0x18`） | 诊断，不阻塞 D2 |

## 5. 风险与停止条件

- `KERNEL-PANIC-01`：同构建可 PASS/panic/PASS；任何 panic 判定需同构建复现 + 冷机复跑，单次 panic 只记录不归因。
- D1 引入内核页喷洒即新增 UAF 面：若门禁出现 `chain` 未动但 panic 新发，**停本批**，回退到 `ce448666` 重跑对照（“不写是否就不崩”的干净对照已在批次 A 拿过，本次对照的是“喷洒是否引入新崩”）。
- `cmp_disasm` 出现 `SHAPE-DIFF`/`OPERAND-DIFF`（非 `LAYOUT-SHIFT`）→ 停并调查。
- OQ1 无结论前不得合入任何 `pread64`-on-pipe 代码（`ESPIPE` 噪声会污染日志口径）。
- fork 版（若走到 OQ3-B）必须先过 §6 的所有权追加行。

## 6. 所有权与生命周期增补（AGENTS.md 强制，追加到原 §4 表）

| 对象 | 起点 | 所有者 | 访问者 | 终结点 | 释放者 |
|---|---|---|---|---|---|
| 喷洒页（D1 新增引用） | `prepare_kernel_page`/kernelsnitch 碰撞 | `ExploitSession.heap`（既有） | `execute()` 投递窗口内只读 | `destroy()` | 既有堆释放路径；worker（若有）必须先停 |
| 控制管命令字节（D2） | `prepare()` | `FdGraphRoute`（`pipe_read`/`pipe_write`，已有） | 投递循环当轮 | `destroy()` | `reset()`；stuck 时并入既有兜底 |
| `ChildProcess`（仅 OQ3-B） | D2 fork 点 | `FdGraphRoute` | 父进程 `waitpid` 240 s | `mark_reaped()`/析构 | `terminate_and_wait(SIGKILL)` 兜底 |

既有不变量保持：`disarm()` 先于 `destroy()`；`stop_consumer` 先于 join；
`consumer_stuck` 兜底路径不变；UAF 例外仅限被回收的 `pipe_buffer` 槽位本身。

## 7. 验证矩阵

| 步骤 | 命令 / 动作 | 预期 |
|---|---|---|
| host | `make -C src native-host-tests` | 21+ suites 全过（含 helper/模式/重试边界新向量） |
| build | NDK 构建 | 零警告 |
| lint | `make -C src lint-tidy` | 0 findings |
| 反汇编 | `python3 tools/cmp_disasm.py <基线> build/native/ghostlock` | 8 函数 `IDENTICAL` 或已注解 `LAYOUT-SHIFT`；`SHAPE`/`OPERAND` 即停 |
| OQ 实验 | 非门禁单跑（见 §4） | 只读优先；任何写目标实验走完整门禁前置 |
| 门禁 | 冷启动 + `tools/gate_preflight.py` 6/6 + 单 route + 固定 CPU 对 + KernelSU 未加载 | `GRAPH_READY`、`payload_writes 240/240`、`chain_hit`/`bit4` 按模式判据；成败同等归档到 `docs/analysis/device-gates/` |
| 成功定义 | W1 `enforce != '1'` + 无 panic（单次不归因，复现确认） | 方可标 supported（另起归档批） |

## 8. 提交切分（每批一原子提交，验证通过才进下一批）

1. `feat(route/fd_graph): D1 reclaim spray/inject placement + PIPE_TARGET log`（host 全绿 + `cmp_disasm`）
2. `feat(route/fd_graph): D2 W-command gate + honest detection accounting`（同上）
3. `feat(route/fd_graph): D3 enforce-file acceptance`（同上；含 OQ1 结论）
4. `feat(route/fd_graph): D4 retry-boundary vectors + tests`（host 全绿）
5. `docs: PROFILE-61258-0X gate archive`（成败同等）

回滚：逐提交 revert 即可；profile/wire 无变更，无数据迁移。

## 9. 评审要点（请确认）

1. **顺序**：D1（喷洒落位）→ D2（门控+检测）→ D3（验收）→ D4（边界）是否认可？OQ1 是否同意先行（它决定 D2-3 的写法）？
2. **致命语义**：`resize` 回读不符，沿用参考的“致命”还是本计划的“放弃本轮”？本计划选后者（进程存活才能跑满 15 attempts，有利归因），是否接受该偏离？
3. **fork**：是否同意 OQ3 的“先单线程、不行再 fork”？若你倾向直接上 `ChildProcess` fork 版，我把 D2 重写为 fork-first。
4. **验收**：W1 成功判据定为 `enforce != '1'`（重试一次），`chain`/`bit4` 只作诊断，是否认可？
