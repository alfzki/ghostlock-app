# `fd_graph` spray-mass（fork children）计划（L 级，待评审）

**状态：待用户评审。评审通过前不得改动攻击关键路径代码。**

依据：`docs/analysis/fd-graph-primitive-scoping.md`（§2.7/§2.10–§2.12、§2.16）、
`decompiled/annotated.c`（`known_page` spray/prepare 段、`FUN_002201d0`、
`worker_pool`、`redirect`/`wait_child`）、门禁 `-05`–`-09`。
父计划：`docs/development/61258-fdgraph-detection-plan.md`（OQ1 已答，OQ2 精化见下）。

## 1. 动机：喷洒面的另一半

门禁 -09 只落地了喷洒面的一半（`collisions` 4→8，31/31 通过、无 panic）。
参考实现的另一半是 fork 群：`spray_children` 最多 fork 150 个子进程并持有
`/proc/<pid>/mem`（`O_CLOEXEC`），配合 order-3 slab 整形（`mm_size=1280`、
`order=3`、`pipe_ring=0x500` 同尺寸类），使被释放的管环页被受控 slab 重占。
`prepare_children`（800×，门控旗标）是 PID 采集前置；`spray_children`
（150×=`0x96`，`DAT_00268038` 门控）是实际持握。子进程 `sched_yield` 空转，
事后有界回收（逐个 `close` + `kill`/`wait`，149 轮）——不是永久泄漏。

OQ2 精化结论：要回答的不是“small 与 expand 之间加不加喷洒”，而是
“expand 释放的页是不是我们预先占好的 slab”。fork 群即占位手段。

## 2. 落点设计（相对 `5210e4e8` 的增量，单变量）

位置：`FdGraphRoute::execute()` 内 `GRAPH_READY` 之后、建管之前
（与参考 `known_page_prepare → reclaim` 顺序一致；kernelsnitch 碰撞扫描
仍在 backend 预路由阶段，本批不动）。

```
spray_reclaim_mass(kFdGraphSprayMax = 150):
  t0 = monotonic_now()
  spawned = 0
  for i in [0, 150):
    pid = fork()
    if pid == 0: { for (;;) pause(); _exit(0); }   // 子进程：只空转，不碰任何 RAII
    if pid < 0: break                              // 优雅降级：保留已产出部分
    open /proc/<pid>/mem O_CLOEXEC → mfd
    if mfd < 0: { terminate该child; break; }        // 无 fd 的 child 不持握
    spray_children.emplace_back(pid)               // support::ChildProcess
    spray_mems.emplace_back(mfd)                   // support::UniqueFd
    spawned++
  log: spray_children count=%u fds=%d elapsed_ms=%llu
```

- 子进程纪律沿用 `attack/ops.cpp slab_drain`（`pause()` 后 `_exit(0)`，不跑任何 RAII 析构）
- 父进程对每个成功 fork 持握一对（`ChildProcess` + `/proc/<pid>/mem` 的 `UniqueFd`），
  fork/`open` 任一失败即停并保留已产出部分（S2 优雅降级），`execute()` 内记
  `spray_children count=%u fds=%d`（计数与有效 fd 数双通道互验）

## 3. 所有权与生命周期（AGENTS.md 强制，追加到原 §4 表）

| 对象 | 起点 | 所有者 | 访问者 | 终结点 | 释放者 |
|---|---|---|---|---|---|
| `spray_children`（`vector<ChildProcess>`） | `spray_reclaim_mass()` | `FdGraphRoute` | 无（仅持有） | `destroy()` | 逐个 `valid()` 则 `terminate_and_wait(SIGKILL)` 后 `clear()` |
| `spray_mems`（`vector<UniqueFd>`） | 同上（与 child 一一配对，不变量：两表等长且槽位一一对应） | `FdGraphRoute` | 无 | `destroy()` | `clear()`（析构逐个 `close`） |
| fork 失败/半程 | 循环内 `break` | 同上 | 无 | 同上 | 已产出部分照常终结，未产出槽位不存在 |

既有不变量保持：`disarm()` 先于 `destroy()`；`stop_consumer` 先于 join；
`consumer_stuck` 兜底路径内新增两表 `release_to_handoff()`/`release_to_process_lifetime()`
后 `clear()`（stuck 时内核仍可能引用，不关不杀，只移交进程期持有）；
UAF 例外仍仅限被回收的 `pipe_buffer` 槽位本身。

## 4. 验证矩阵

| 步骤 | 命令 / 动作 | 预期 |
|---|---|---|
| host | `make -C src native-host-tests` | 全过；新增 `kFdGraphSprayMax==150` 断言 + `spray_reclaim_mass(2)` 功能向量（数量≤请求、成员一致、`destroy()` 后清空；沙箱禁 fork 时优雅为 0，仍具决定性） |
| build | NDK 构建 | 零警告（`fork`/`pause`/`_exit`/`open`/`snprintf` 均为 bionic 可用） |
| lint | `make -C src lint-tidy` | 0 findings（`%d` 配 `static_cast<int>(pid)`；`size_t` 比较显式转换） |
| 反汇编 | `python3 tools/cmp_disasm.py <基线> build/native/ghostlock` | 8 函数 `IDENTICAL` 或已注解 `LAYOUT-SHIFT`；新增 `SHAPE` 即停并按 gate-08 先例反汇编核查 |
| 门禁 | 冷启动 + `tools/gate_preflight.py` 6/6 + 单 route + 固定 CPU 对 + KernelSU 未加载 | `spray_children count=150 fds=150`、其后 `GRAPH_READY` 等既有行不变、无 panic、进程自主退出；成败同等归档 |

## 5. 风险与停止条件

- 新增 fork 面：单轮 150 `fork` + 150 `/proc/pid/mem` open，fd 预算峰值约 25.5k < 32768（`BulkFdOwner` 24674 + 管道 480 + 喷洒 150 + 余量），`RLIMIT` 前置检查已覆盖。
- `KERNEL-PANIC-01`：任何 panic 需同构建复现 + 冷机复跑才可归因；单次只记录。
- 子进程只 `pause()` 不映射不写字；父进程只 `open` 不读写 mem fd——本批**不产生新的内核写面**，只有进程/页引用计数变化。
- `cmp_disasm` 新增 `SHAPE-DIFF` → 停并调查（gate-08 的 erratum 存根先例可直接比对）。
- 门禁出现 panic 且同构建可复现 → 停本批，回退到 `5210e4e8` 跑对照。

## 6. 评审要点（请确认）

1. **数量**：150（=参考 `0x96`）一次到位，还是先 32 只验安全再加码？本计划选 150（单变量即 fork 面本身，数量是其内禀部分）。
2. **失败语义**：fork/`open` 中途失败即停并保留部分（S2），而不是整轮放弃——是否接受？
3. **stuck 兜底**：`release_to_handoff()` + `release_to_process_lifetime()` 后 `clear()`，是否认可该语义？