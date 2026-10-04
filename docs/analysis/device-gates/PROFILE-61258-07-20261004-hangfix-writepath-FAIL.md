# PROFILE-61258-07-20261004 — hang 修复 + `write()` 投递通路：进程自主退出，投递仍 `chain_hits=0`（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`99a326d` + 未提交工作树（hang 修复 + `write()` 通路 + 检测 helper；`GENMARK0` 笔误已正名），二进制 sha256 `ce448666f063bdcbe70e15546c5c1802af93caef06a0d838c422e884aec000d5`（短 `ce448666f063bdcb`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `550d1b0f4057a404f84e5233d12e96d14926d879f1b400b7c35ddd0258e76d4b`（与批次 A 同值，本批未改 profile）
- **改动**（相对门禁 -06 的 `9af305a2`）：
  1. hang 修复：`consumer_thread_fn` 的 `epoll_wait(..., -1)` 改为 100 ms 量子 + `stop_consumer` 原子检查；`disarm()` 先置旗再 join。`destroy()`/stuck 兜底不动。
  2. RACE 环 `vmsplice` 改 `write()` 逐槽全长校验（参考原语的 syscall，`payload_writes ok/total` 口径），`redirect mode=` 日志 + helper 判据（`zero_byte_redirect`/`pipe_flags_candidate`）。`chain_hit`/`bit4` 保持诚实零值（无内核读回前不虚报）。
  3. `GENMARK0` 笔误正名 → `0x304b52414d4e4547`（本次门禁日志已确认 `generation=304b52414d4e4547`）。
- **原始证据**：`logs/gate-20261004-hangfix/`（`native.log` 64616 B、`binary.sha256`、`profile.sha256`、`build_commit.txt`、`bootreason.txt`）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime 56750 ms（< 120000 ms） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| 进程终态 | **自主退出 exit=1** ✅（首次：不再需要 `timeout` 击杀；exit `124` 消失） |
| `route_done` + `threads joined` | **13/13** ✅（每次建图后均正常握手终结） |
| `CMP_REQUEUE_PI` | ret=1 errno=0，每轮 ✅（W1 PI 窗口保持） |
| `GRAPH_READY` | 13 次 width=96 fanout=256 edges=24576 ✅（星形拓扑保持，无 `ELOOP`） |
| `reclaim_small` / `resize_sample` 双阶段 | 13/13 ✅ |
| `payload_writes ok=240 total=240` | **130/130** 轮 ✅（13 运行 × 10 轮，共 31,200 次全长 `write`，零短写） |
| `redirect mode` | `zero_byte_redirect needs_bit4=0` ✅（W1 Zero 模式映射正确） |
| `KNOWN_PAGE` / `GENMARK` | `fake_fllink=base\|0x108` ✅，`generation=304b52414d4e4547` ✅（笔误修复落地） |
| `RACE` / `RACE_SUMMARY` | 全部 `chain_hit=0 bit4=0`，`delivery=not-implemented`，target=`ffffff80027c6960` |
| W1 全程 | 15/15 attempts 跑完 → `W1: SELinux attempt 15 route failed` → `Write 1 failed`（`PI route did not produce a verified write`） |
| SELinux | Enforcing（W1 未翻，预期内） |
| panic | **无**（跑后 uptime 连续 28 s → 118 s，`sys.boot.reason=reboot,shell`） |

**判定：FAIL**（W1 未完成，`chain_hits=0`）。但本批两个目标全部达成：exit `124` 挂起消除（13/13 正常终结），`write()` 通路 130/130 全长成功。

## 说明

1. **13 vs 15**：W1 共 15 attempts，其中 13 次进入 route（`GRAPH_READY` ×13）；另 2 次在堆喷洒/页准备阶段即重试，未进 route。`threads joined` ×13 与建图次数一致——每次进 route 的都干净退出了。
2. **`chain_hits=0` 是诚实值**：`chain_hit` 仍为硬编码初值，`fd_graph_round_success()` 在此输入下恒为假，故 `FLAGS_CANDIDATE`/`RESULT PASS` 不可达。 gates -06 记录的下一批内容不变：槽位选取 + `RECLAIM_HIT` + `pread64` 按槽位回读 + `marker_changed`，判据 scoping §2.18.2。
3. **`pread64` 仍未引入**：管道不支持 `pread`（`ESPIPE`），参考实现的回读 fd 归属尚未确证；宁缺勿滥，留待取证后再定。
4. **单次无 panic 不构成因果结论**（`KERNEL-PANIC-01`）：本记录只断言本次运行无 panic。

## 门槛

- host tests 21 suites（含 14 个新增 helper 向量）/ NDK 零警告 / lint-tidy 0 findings
- `cmp_disasm` 真基线 diff（`99a326d` 干净树 vs 本批）：6× `OPERAND-DIFF`，指令数逐项一致，全部差异为 `ldr`/`add` 偏移+立即数字面量平移（结构体增大所致），**零**分支/调用/助记符变化 → 已注解的 `LAYOUT-SHIFT` 类，无逻辑漂移
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 6/6
- 设备侧二进制 sha 与本地一致（`ce448666f063bdcb`）

## 下一步

1. 下一批实现真正的投递检测（见上 §说明 2），仍需真机门禁。
2. `exit 124` 任务关闭（本门禁 13/13 终结即证据）。
3. 本批二进制与门禁 -06 的差集仅为 teardown + RACE 环 syscall + helper，无 UAF 面变化；`LAYOUT-SHIFT` 注解随本记录归档。
