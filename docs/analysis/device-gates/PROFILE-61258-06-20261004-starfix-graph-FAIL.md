# PROFILE-61258-06-20261004 — epoll 星形拓扑修复：ELOOP 消除、`GRAPH_READY` 达成，但投递仍 `chain_hits=0`（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`99a326d` + 未提交工作树（`fd_graph_route.cpp` 星形拓扑重写、`native_resource.*` 的 `BulkFdOwner`、`native_resource_test.cpp` 新增向量），二进制 sha256 `9af305a22e0bb9eefde01cf333c988b9b08eedcab75d82362324811c6c1d7c62`（短 `9af305a22e0bb9ee`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `550d1b0f4057a404f84e5233d12e96d14926d879f1b400b7c35ddd0258e76d4b`（与批次 A 同值，本批未改 profile）
- **改动**：`FdGraphRoute::execute()` 的嵌套 epoll 建图由单链（`prev_epoll` 跨全部 24,576 次迭代传递）改为星形（seed 对 + 96 个每宽基址，各带 256 个子节点只注册所属基址，深度恒为 1），并在失败路径补齐已建 fd 的关闭（原失败路径只 `delete[]` 数组，漏关 fd）；`errno` 改为 syscall 失败后立即暂存再打印
- **依据**：`decompiled/annotated.c` graph 段（`uVar12` 为每宽基址，内层 256 次 `epoll_ctl(new, ADD, uVar12)`，`GRAPH_READY width=96 fanout=256 edges=24576`）；scoping §2.16 原文“每个把上一个 epoll 的 fd 注册进去”实为“每个注册所属每宽基址”，本文档即该勘误
- **原始证据**：`logs/gate-20261004-starfix/`（`native.log` 6952 B、`binary.sha256`、`profile.sha256`、`build_commit.txt`、`bootreason.txt`）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime 33410 ms（< 120000 ms） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| `CMP_REQUEUE_PI` | **ret=1 errno=0** ✅（W1 PI 窗口仍活，批次 05 的修复保持） |
| `FD_LIMIT_INITIAL` | cur=32768 max=32768 graph_only=24736 ✅ |
| `GRAPH_READY` | **width=96 fanout=256 edges=24576** ✅（首次达成；上一版在此处 `epoll_ctl ADD failed at 6 errno=40` 即 `ELOOP`） |
| `ELOOP`/建图失败 | **无** ✅（24,674 个 epoll fd：seed 对 2 + 基址 96 + 子节点 24576，全建链成功） |
| `reclaim_small` | complete fds=240 ✅ |
| `resize_sample` | reclaim_small / reclaim_expand 各 240 ✅（回读校验通过，无 `resize_fail`） |
| `KNOWN_PAGE` | base=0x0000007739980000 fake_fllink=base\|0x108 ✅（形式正确） |
| `RACE` | 10/10 轮 `chain_hit=0 bit4=0`，`RACE_SUMMARY tries=10 pipe_fill_hits=2400 chain_hits=0 bit4_hits=0 delivery=not-implemented target=ffffff80027c6960 |
| SELinux | Enforcing（W1 未翻，预期内） |
| panic | **无**（跑后 uptime 连续 28 s → 185 s，`sys.boot.reason=reboot,shell`，`ro.boot.bootreason=reboot`） |
| 进程终态 | `timeout 120` 击杀 → exit `124`（与批次 A 相同的挂起：route 返回 `ROUTE_RETRYABLE` 后进程不退出，属既有生命周期缺陷，与本批无关） |

**判定：FAIL**（W1 未完成，`chain_hits=0`）。但建图阻塞已解除：上一版的 `ELOOP` 在本批复现窗口内消失，`GRAPH_READY` 稳定达成。

## 说明：为何 `chain_hits` 仍为 0（预期内，非回归）

本批只做了“把图建成且不触发内核嵌套守卫”——`execute()` 的 RACE 环仍是脚手架：`chain_hit`/`bit4` 为硬编码初值，没有实现真正的槽位选取、`fd_table` 240 路 `write`、`pread64` 按槽位回读与 `marker_changed` 判定。因此 10 轮全零是实现完整度的如实反映，不是机制被证伪。真正的投递检测是下一批的内容。

## 附带发现（本批必须记录的三项）

1. **`GENMARK0` 常量笔误**：本批二进制喷入的是 `0x304b5214d4e4547`，正确值应为 `0x304b52414d4e4547`（小端 `"GENMARK0"`，scoping §2.19.1）。本次门禁中该标记未被任何读回消费，故对本轮结果**零影响**；已列为合并前必须修复项。
2. **进程挂起是既有缺陷**：exit `124` 与批次 A（`PROFILE-61258-02`）逐字同因——`ROUTE_RETRYABLE` 后无退出路径。不得在本批顺手修（与攻击路径无关，另立任务）。
3. **单次无 panic 不构成因果结论**：按 `KERNEL-PANIC-01`，同构建需复现 + 冷机复跑才能判定。本记录只断言“本次运行无 panic”，不断言“本批消除 panic”。

## 门槛

- host tests 21 suites / NDK 零警告 / lint-tidy 0 findings / `cmp_disasm` 自比较 `RESULT: PASS`（6 个攻击函数 `IDENTICAL (strict)`，2 个 multicast `STALE`，符合预期）
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 6/6
- 设备侧二进制 sha 与本地一致（`9af305a22e0bb9ee`）

## 下一步

1. 修 `GENMARK0` 笔误 → `0x304b52414d4e4547`（无行为变化，但必须在检测逻辑落地前正名）。
2. 下一批实现真正的投递检测：槽位选取 + `RECLAIM_HIT` 双模式判据 + `fd_table` 240 路 `write`（`'W'` 门控、全长校验）+ `pread64` 按槽位回读 + `marker_changed`，成功判据沿用 scoping §2.18.2（`chain_hit==1` **且** `bit4==1`）。
3. 进程挂起（exit `124`）另立任务定位（候选：`route_done` 握手 / `consumer_thread` 终结 / `disarm` 顺序），不得与攻击路径改动混批。
