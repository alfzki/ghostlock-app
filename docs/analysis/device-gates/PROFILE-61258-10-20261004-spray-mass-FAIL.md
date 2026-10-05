# PROFILE-61258-10-20261004 — spray-mass（150 fork 持 `/proc/pid/mem`）：全数存活回收，投递仍 `chain_hits=0`（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`e032c88` + 未提交工作树（spray-mass 一批），二进制 sha256 `929ccf80ef0880dd4cb7c6150fa26ff5ca06dc56af278bb58bfc3a7371c97465`（短 `929ccf80ef0880dd`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`（collisions=8，自门禁 -09 未变）
- **改动**（相对门禁 -09 的 `5210e4e8`，单变量即 fork 喷洒面）：
  1. `FdGraphRoute::spray_reclaim_mass(kFdGraphSprayMax = 150)`：`GRAPH_READY` 后、建管前逐个 `fork`，子进程 `pause()` 空转（`_exit(0)` 兜底，不碰 RAII），父进程持握（`ChildProcess` + `/proc/<pid>/mem` 的 `UniqueFd`，`O_CLOEXEC`）；`fork`/`open` 任一失败即停并保留已产出部分。
  2. `destroy()` 终结已产出（逐个 `terminate_and_wait(SIGKILL)` 后 `clear()`）；`consumer_stuck` 兜底改为 `release_to_handoff()` + `release_to_process_lifetime()` 后 `clear()`。
  3. `kFdGraphSprayMax == 150` 断言 + `spray_reclaim_mass(2)` 功能向量（数量≤请求、成员一致、`destroy()` 后清空；沙箱禁 fork 时优雅为 0）。
- **原始证据**：`logs/gate-20261004-spray/`（`native.log` 68700 B、`binary.sha256`、`profile.sha256`、`build_commit.txt`）
- **设计文档**：`docs/development/61258-fdgraph-spray-plan.md`（L 级，含所有权表与停止条件）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime ~29 s（< 120000 ms） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736（峰值约 25.5k：24674 epoll + 480 管道 + 150 喷洒 + 余量） |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| `spray_children count=150 fds=150` | **14/14** ✅（每轮约 200 ms；`fork` 零失败、`open` 零失败） |
| 进程终态 | **自主退出 exit=1** ✅（2250 fork/close/waitpid 循环后无僵尸、无挂起） |
| `GRAPH_READY` / `PIPE_TARGET` / `cmd_gate` / `payload_writes` / `enforce` | 与门禁 -08 同形，全通 ✅ |
| `RACE_SUMMARY` | `chain_hits=0 bit4_hits=0 delivery=not-implemented`（诚实零值） |
| `route_done` + `threads joined` | **14/14** ✅ |
| W1 全程 | 15/15 attempts 跑完 → `Write 1 failed` |
| SELinux | Enforcing（预期内） |
| panic | **无**（跑后 uptime 连续 29 s → 101 s，`sys.boot.reason=reboot,shell`） |

**判定：FAIL**（W1 未完成）。但喷洒面安全目标达成：150 fork + 150 memfd + 全数回收往返 14 轮，无泄漏、无挂起、无 panic。

## 说明

1. **14 vs 15**：15 attempts 中 14 次进入 route（1 次在堆喷洒阶段即重试），`spray_children` ×14 与建图次数一致。
2. **fd 预算验证**：`enforce_open` fd 号落在 ~25k 区间（OQ1 探针结论一致），`RLIMIT` 余量模型成立。
3. **单变量归因**：相对 -09 仅加 fork 喷洒面；“无新 panic”可直接归因于该变量安全。
4. **剩余缺口**：喷洒页尚未与管环回收形成重占（`inject`），`RECLAIM_HIT`/`marker_changed` 仍待内核读回；`pread64` 不得用于管道/epoll（OQ1：`ESPIPE`）。
5. 单次无 panic 不构成因果结论（`KERNEL-PANIC-01`）。

## 门槛

- host tests 21 suites（含喷洒常量 + 功能向量）/ NDK 零警告 / lint-tidy 0 findings
- `cmp_disasm` 真基线：6× `OPERAND-DIFF`（计数逐项一致，纯偏移平移）+ 零分支/调用变化 → 已注解 `LAYOUT-SHIFT` 类；`SHAPE-DIFF` 在本次基线重建后未复现（门禁 -08 的 erratum 存根为单次布局产物，见该记录 §说明 2）
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 6/6
- 设备侧二进制 sha 与本地一致（`929ccf80ef0880dd`）

## 下一步

喷洒持有面已验证安全；下一次 L 级工作的主题是喷洒页→释放环的**重占时序**（OQ2：small→喷→expand 交错）与触发后的**内核读回**。在此之前不得标 supported。
