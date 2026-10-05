# PROFILE-61258-14-20261004 — fork redirect（子进程投递 + 父进程 120 s 有界等待）：24/24 干净回收，附一次 owner-ESRCH 中断（FAIL）

- **日期**：2026-10-04（主跑 + 同构建复现跑）
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`e032c88` + 未提交工作树（fork 一批），二进制 sha256 `9aa1a70a829dfabfbafa86b786560e80f0d74b9ecc7ade188ed43a6ab51942ff`（短 `9aa1a70a829dfabf`，两轮均核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`（自门禁 -09 未变）
- **改动**（相对门禁 -13 的 `86969d35`，单变量即进程拓扑）：RACE 环移入 fork 子进程（`write`/`usleep`/`_exit`，禁 `printf`/`malloc`，3 字节状态 `/轮` 经状态管回传）；父进程 `ChildProcess` 持有 + `WNOHANG` 轮询 1200×100 ms 上限 + 超时 `SIGKILL` + `mark_reaped()` + 排空解码；`fork < 0` 直接警告返回（不降级 inline）；其余（汇总/enforce/清理/decoy）逐行不动。
- **原始证据**：`logs/gate-20261004-fork/`（`native.log` 51246 B，主跑） + `logs/gate-20261004-fork-repro/`（`native.log` 61767 B + 两 sha + commit，同构建复现跑）
- **设计文档**：`docs/development/61258-fdgraph-trigger-plan.md` §8（120 s vs 参考 240 s 等三项偏离已记录理由）

## 门禁前置（两轮均 `tools/gate_preflight.py` 6/6 PASS；复现轮冷启动 29 s）

主跑/复现跑：设备唯一、KernelSU 未加载、`uname -r` 精确匹配、`RLIMIT_NOFILE` 32768、Asleep+locked（记录项）。复现轮与主跑同构建、同 profile。

## 结果（两轮合并）

| 项 | 主跑 | 复现跑 |
|---|---|---|
| 进程终态 | exit **255**（见下） | exit 1（自主） |
| `redirect spawn` → 10× `redirect RACE` → `redirect complete rc=0 rounds=10` | 11/11 ✅ | 13/13 ✅ |
| `fork failed` / `redirect timeout` | 零出现 ✅ | 零出现 ✅ |
| `GRAPH_READY` / `spray 150/150` / `PIPE_TARGET` / `cmd_gate` / `payload_writes` / `enforce state=0` / `decoy_unlink rc=0` | 全通 ✅ | 全通 ✅ |
| `route_done` + `threads joined` | 11（中断） | 13 ✅ |
| W1 attempts | ~11（被截断） | **15/15 跑完** → `Write 1 failed` |
| `RACE_SUMMARY` | `chain 0` 诚实 | `chain 0` 诚实 |
| SELinux / panic | Enforcing / 无 | Enforcing / 无（28 s→100 s 连续） |

**fork 通路结论：24/24 干净投递回收**（spawn→10 轮→complete rc=0→route_done→join，零 fork 失败、零超时、零僵尸）。**判定：FAIL**（W1 未完成，符合预期——无 inject 即无 chain）。

## owner-ESRCH 中断事件（主跑 attempt 11，复现跑未复现 → 不归因）

- 现象：`W1 attempt 11/15` 的 route 完成后，owner 线程 `FUTEX_LOCK_PI(target_futex)` 返回 `ESRCH`（errno 3），`pr_error` 触发 → `exit(-1)` → 全进程 exit 255，后续 attempts 丢失。
- 机制链（已证实）：`race/threads.cpp:95` 的 `pr_error` 展开自 `kernelsnitch/utils.h`，**四个变体全部以 `exit(-1)` 结尾**——因此任何一次 owner 抖动都会杀死整个 15-attempt 进程。这是既有代码（本批未触及 race/ 目录），不是 fork 引入的新路径。
- 归因：13 门禁累计数百 attempts 中首次出现；同构建冷启动复现跑 15/15 干净跑完。按 `KERNEL-PANIC-01` 类比原则：**单次、未复现，不归因于 fork**。fork 嫌疑保持“未排除但无证据”——若未来复现，首选对照是同条件重跑（fork 面是唯一进程拓扑变量）。
- 衍生发现（与 fork 无关，建议后续硬化，不在本批）：per-attempt 的 owner 竞态失败会终结整个门禁进程；应改为 per-attempt 失败（`ROUTE_DIRTY_FAILURE`）而非 `exit(-1)`。改动面在 `race/threads.cpp`，需独立批次。

## 门槛

- host tests 21 suites（含退出码编解码 + 延迟表 + 轮询上限向量）/ NDK 零警告 / lint-tidy 0 findings
- `cmp_disasm` 真基线：6× `OPERAND-DIFF`（计数逐项一致）+ 零分支/调用变化 → 已注解 `LAYOUT-SHIFT` 类（本批 SHAPE-DIFF 未复现）
- 冷启动 + `tools/gate_preflight.py`：两轮 6/6
- 设备侧二进制 sha 与本地一致（`9aa1a70a829dfabf`）

## 下一步

fork 拓扑已证安全可用；`chain` 仍待真实 inject（喷洒页→释放环重占 + 触发变体）。在此之前不得标 supported。
