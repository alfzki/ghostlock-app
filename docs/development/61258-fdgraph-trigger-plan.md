# `fd_graph` trigger-leg conformance plan — `decoy_unlink` 本批，fork 递延（L 级，待评审）

**状态：待用户评审。评审通过前不得改动攻击关键路径代码。**

依据：`fd-graph-primitive-scoping.md`（§2.5.1/§2.5.2/§2.8/§2.9/§2.17/§2.18.1）、
`decompiled/annotated.c`（`EPOLL_CTL_DEL` 站点 `0x221acc`、RACE 环 `5535`–`5600`、
`redirect`/`wait_child`）、门禁 `-05`–`-11`。

## 1. 目标与非目标

**目标**：补齐 trigger 环节中唯一缺失的结构件——触发后的 `decoy_unlink`
（`EPOLL_CTL_DEL`，`event=NULL`），并验证其在真机上的行为与日志口径。

**非目标**：
- fork redirect（OQ3-B）：ChildProcess 基础设施就绪，但 fork 改变进程结构，
  按单变量原则递延到下一批；本批保持单线程投递。
- 写入目标/载荷变更：仍写 240 drain 写端、全长校验（门禁 -07 已证 240/240）。
- `fake_fllink` 语义变更：`base | 0x108` 保持（诊断日志已有）。
- 任何成功判据变更：`chain_hit` 保持诚实零值；验收仍走 enforce 文件。

## 2. 参考行为（行级证据，两 agent 交叉确认）

| # | 行为 | 出处 |
|---|---|---|
| 1 | 240 路 `write(fd, buf, 1)`，任一短写即放弃整轮 | scoping §2.9；`annotated.c` 投递循环 |
| 2 | `'W'`（`0x57`）命令门：先 `read` 1 字节，不符即跳过写 | scoping §2.5.2（`0x220bac: cmp w8, #0x57`） |
| 3 | `EPOLL_CTL_DEL` 是 7 个 `epoll_ctl` 中的最后一个（前 6 为 ADD），`event=NULL` | scoping §2.5.1（`0x221acc`） |
| 4 | `close_after_trigger=1` 硬约束：epoll fd 在触发**后**才关，先关则链断、内核不再遍历投毒项 | scoping §2.18.1 |
| 5 | `redirect` 派生子进程投递、父进程 240 s 超时回收 `rc` | scoping §2.17（本次递延，只记录） |

## 3. 本批改动（单变量：只加 DEL，不碰其他）

- 新增纯函数 `fd_graph_decoy_unlink(epfd, target)`（`epoll_ctl(DEL, NULL)` 薄包装，
  置于 `#if` 之外以便 host 单测；`sys/epoll.h` 已无条件包含）。
- `execute()` 在 RACE 环结束后、管道回收前调用一次：以 star 图第 0 组
  （`child = epoll_fds[3]` 监视 `base = epoll_fds[2]`）为 decoy，
  `DEL(base)` 后记 `decoy_unlink child=%d base=%d rc=%d errno=%d`；
  `rc != 0` 只记日志，不改变 route 结果（无毒化链可摘时 DEL 本就该失败，
  失败是信息，不是故障）。
- `close_after_trigger` 天然成立：epoll fds 只在 `destroy()` 的 `BulkFdOwner::reset()`
  里关闭，远在 trigger/detect 之后；本批不碰该顺序。
- fork 不动：单线程投递保持；`ChildProcess` fork 版留待 OQ3-B 批次。

## 4. 所有权与生命周期

零新增：无新成员/全局/线程/fork；DEL 操作无所有权转移；
`errno` 调用后立即暂存再打印（ELOOP 教训）。

## 5. 验证矩阵

| 步骤 | 命令 / 动作 | 预期 |
|---|---|---|
| host | `make -C src native-host-tests` | 全过；新增 decoy 向量（真 epoll 上 ADD→DEL 返回 0，重复 DEL 非零；不依赖 device） |
| build | NDK 构建 | 零警告 |
| lint | `make -C src lint-tidy` | 0 findings |
| 反汇编 | `python3 tools/cmp_disasm.py <基线> build/native/ghostlock` | 8 函数 `IDENTICAL` 或已注解 `LAYOUT-SHIFT`；新增 `SHAPE` 即停并反汇编核查 |
| 门禁 | 冷启动 + `tools/gate_preflight.py` 6/6 + 单 route + 固定 CPU 对 + KernelSU 未加载 | `decoy_unlink ... rc=0`（首轮 feasibly；若 `ENOENT` 类非零则记为信息）；其余行与 -11 同形；`chain 0` 诚实；无 panic；自主退出；成败同等归档 |

## 6. 风险与停止条件

- DEL 目标是真实注册过的对子（child[3] 确含 base[2]，建图期写入），`EBADF`/`ENOENT` 只应出现在重复/错乱时；`rc != 0` 不 abort、不改判据。
- `KERNEL-PANIC-01`：任何 panic 需同构建复现 + 冷机复跑；单次只记录。
- `cmp_disasm` 新增 `SHAPE-DIFF` → 停并调查（gate-08 先例流程）。
- 本批不产生成功信号的预期是**明确的**（无 inject 即无 chain）；门禁价值 = DEL 通路证明 + 安全回归。

## 7. 评审要点（请确认）

1. decoy 取第 0 组（child[3]/base[2]）是否可接受？替代是每轮 DEL/重建（扰动大，不建议）。
2. `rc != 0` 只记不判——是否接受该弱断言？（强断言会把“无毒可摘”的诚实状态误判为失败。）
3. fork 递延到 OQ3-B 是否同意？

## 8. OQ3-B fork redirect 设计（2026-10-04，用户点名执行）

前序门禁（-12/-13）证明单线程投递结构安全但 `chain` 恒零；`fork` 是参考实现
中唯一尚未移植的进程拓扑件。本批只做 fork，不碰写入目标/载荷/判据。

### 架构（单次 `fork` 包裹 RACE 环，逐 W1 attempt 一次）

- 子进程：精简触发循环（共享延迟表；每轮 `usleep` → 240 路 `write` 全长校验 →
  staging 读 `can_merge`/`marker` → 状态管写 3 字节 `[chain, bit4, payload_ok]`
  → 本轮判据成立即提前 break；循环结束 `_exit((chain?1:0)|(bit4?2:0))`）。
  子进程只调用 `usleep`/`write`/`read`（无）/`close`（仅状态管读端）/`_exit`，
  不碰 `printf`/`malloc`/`pthread`/任何 RAII 析构（`_exit` 直接终结）。
- 父进程：`fork` 前建好状态管（`pipe2` CLOEXEC，父持读端，`fork` 后即关写端）；
  `ChildProcess` 持有 pid；`waitpid(WNOHANG)` + `usleep(100000)` 轮询，上限
  1200 轮（≈120 s，相对参考 240 s 的偏离见下）；正常回收即 `mark_reaped()`，
  排空状态管（上限 64 B，多余丢弃），逐轮记 `redirect RACE ...` 日志；
  超时则 `terminate_and_wait(SIGKILL)` 并记超时，`chain` 保持为假。
- `fork < 0` 时不降级 inline，直接记警告回 `RETRYABLE`（资源耗尽时继续 hammer
  是错的；backend 的 15 attempts 会重试；`destroy()` 的 RAII 兜底保证无泄漏）。
- 退出码只传 bit0=`chain`、bit1=`bit4`；`pipe_fill_hits` 由状态字节累加；
  其下游（汇总、enforce、清理）逐行不动。

### 偏离记录（相对参考，均有理由）

1. 超时 120 s 而非 240 s：门禁预算 280 s + 外层 300 s `route_done` 兜底；
   子进程名义工作量 < 5 s，120 s 已是 20 倍余量。
2. 状态管为新增件（参考无）：子进程禁用 `printf` 的 fork 安全代价；
   管道 64 KB 默认缓冲远大于 30 B 上限，不会反压子进程。
3. `fork` 失败直接返回而非 inline 重试：耗尽时 hammer 更糟；见上。

### 生命周期

零新成员（状态管/ChildProcess 均为 `execute()` 局部；`destroy()`/`retain()`
两条路径不动）。任何路径下子进程必被回收（成功 `mark_reaped`、超时 kill、
`fork` 失败无子进程、`ChildProcess` 析构兜底）——无僵尸、无泄漏。

### 验证与停止条件

- host：退出码编解码 helper + 共享延迟表断言；子进程体只走真机门禁
  （host 单测不 fork，保证决定性）。
- `cmp_disasm`：6 函数 `IDENTICAL` 或已注解 `LAYOUT-SHIFT`；新增 `SHAPE` 即停。
- 门禁：`redirect spawn/complete` 行 + `redirect RACE` 行出现；`chain 0` 仍为
  诚实预期（无 inject 即无 chain，本批只证明 fork 拓扑安全）；panic 按
  `KERNEL-PANIC-01` 归因；`timeout` 行出现即判本批失败并调查子进程挂因。
