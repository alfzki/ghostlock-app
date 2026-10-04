# PROFILE-61258-05-20261004 — W1 PI race 修复：CMP_REQUEUE_PI 由 EDEADLK(35) → 成功 ret=1（owner 取消预占 target）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：HEAD（rework Wave-1），二进制 sha `a9d160dc6d2a3804d9288a7a7cb97ded81ade3ef0c152d93460ddead15c2fa36`
- **改动**：`src/core/race/threads.cpp` 的 `owner_thread` 把 `target_futex` 的
  `FUTEX_LOCK_PI` 推迟到本线程已提交阻塞在 `chain_futex` 之后（不再预占）。
- **计划**：`docs/development/w1-pifutexrace-rework-plan.md`；
  Oracle 确认根因：owner 预持 `target_futex` 在 requeue 时刻恰好闭合了
  waiter→target→owner→chain→waiter 的 PI 环，内核以 EDEADLK(35) 拒绝 requeue。

## 结果

| 运行 | CMP_REQUEUE_PI | panic | enforce(after) |
|---|---|---|---|
| #1 | **ret=1 errno=0** ✅ | 无（+145 s，`reboot,shell`） | 1 |
| #2 | **ret=1 errno=0** ✅ | 无（+340 s，`reboot,shell`） | 1 |

**稳定复现**：同一二进制、两次冷启动均 `ret=1 errno=0`，且两次均未 panic。
这是本会话首次 W1 requeue 成功、稳定复现、无 panic。

## 说明：W1 仍未翻 SELinux

日志 `W1: SELinux attempt 1/15`，`fd_graph: RACE_SUMMARY …
delivery=not-implemented … chain_hits=0 bit4_hits=0`。
即 **W1 的 PI 窗口已能建立**（CMP_REQUEUE 成功），但 `fd_graph` 的投递体
仍是批次 A 占位的 `not-implemented`，因此 W1 不会真正落成 SELinux 0。
这正说明批次 D 的剩余内容，而当前 Wave-1 的前置（活的 PI 窗口）已成立。

## 门槛

- host tests 21 suites / NDK 0 warning / lint-tidy 0 / gradle 0 FAILED
- `cmp_disasm`: `owner_thread` 由 69 条变 66 条（符合改动）；`waiter_thread`、`consumer_thread`、`run_main_route_threads`、`do_kernel5_fake_lock_route`、`do_one_write` **IDENTICAL (strict)**；两个 multicast worker 在**两侧**均 STALE（5.15 未构建）
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 5/5
- 设备侧二进制 sha 与本地一致

## 结论与影响

futex 竞态握手此前被 `EDEADLK` 锁死、窗口从未建立；本改动后
`FUTEX_CMP_REQUEUE_PI` 稳定返回 1，无 panic。
⇒ 之前困扰的「lane」与「EDEADLK」属同根：owner 的 target_futex 预占构成 PI 环。
⇒ 批次 D 的前置（活的 W1 requeue 窗口）已具备；
  **但 W1 的实际 SELinux 0 仍待 `fd_graph` 投递体（批次 D）实现，
  本里程碑仅解除 race 握手。**