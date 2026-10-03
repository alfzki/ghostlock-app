# PROFILE-61258-04-20261004 — W1 requeue 比较值实验：PASS（假设**部分**证实）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **计划**：`docs/development/w1-requeue-val3-plan.md`
- **改动**：`src/core/race/threads.cpp:184`，`FUTEX_CMP_REQUEUE_PI` 的 `val3` 由 `0` 改为 `1`（**1 个字面量**）
- **基线二进制**：`b5825b42fab08c22e98e78df6faa52b0b5236679647a0b6267f27c4e4a4a2e1e`
- **本次二进制**：`4676dea9fbe547f938be59dce82bff7481c4921ec86066cb3ed2be3146d80a96`（设备侧 sha 一致）
- **原始证据**：`logs/gate-20261004-*/val3run.txt`

## 结果

| | `val3 = 0`（基线） | `val3 = 1`（本次） |
|---|---|---|
| `CMP_REQUEUE_PI` | `ret=-1 errno=35` | `ret=-1 errno=11` |
| errno 名称 | **`EDEADLK`** | **`EAGAIN`** |
| 本次 panic | — | **无**（+270 s uptime，`bootreason=reboot,shell`） |

**errno 改变 ⇒ 假设的前半段证实**：内核确实在比较 `val3`，
原值 `0` 使 `uval != nr_wake` 成立并提前退出；改为 `1` 后比较通过，
syscall 得以继续执行更深的路径。

**但 requeue 仍未成功**：现在以 `EAGAIN` 失败，
即「`wait_futex` 上没有可 requeue 的 waiter」。
⇒ **存在第二个、独立的缺陷**，不是本次 1 行改动能解决的。

## 一处必须更正的既有错误

此前多份记录（含本计划与 `w1-pi-race-review.md`）把 `errno=35` 写作 `EAGAIN`。
核对 NDK `asm-generic/errno*.h`：

```
EAGAIN  = 11
EDEADLK = 35
```

**`35` 是 `EDEADLK`（Resource deadlock avoided），不是 `EAGAIN`。**
且 `race/threads.cpp` / `race/pi_race.cpp` 中**从未出现 `EAGAIN`**，
即代码本身没有对这个 errno 作任何断言或解释 —— 之前的解释纯属我的误读。

这一点使原假设的**起点**也需要修正：`EDEADLK` 是 PI-futex 的经典失败
（调用方与锁持有者构成死锁），而不是「无 waiter」。因此
「`val3` 不匹配导致提前退出」这一解释虽然被本次实验证实了**行为变化**，
但对 `EDEADLK` 的成因解释**并不完整**，可能另有触发 `EDEADLK` 的条件。
已更正的文件：`w1-requeue-val3-plan.md`、`w1-pi-race-review.md`、
`PROFILE-61258-02`、`PROFILE-61258-03`、`61258-panic-attribution-correction.md`。
设备原始 `.log` **未改写**（属证据）。

## 门槛结果

| 门槛 | 结果 |
|---|---|
| `make -C src native-host-tests` | exit 0（21 suites） |
| `make -C src ghostlock` | exit 0，**0 warning** / 0 error |
| `make -C src lint-tidy` | exit 0，**0 finding** |
| `./gradlew :app:testDebugUnitTest :profile-core:test` | exit 0 |
| `tools/cmp_disasm.py` | `run_main_route_threads` **1/413 指令**差异，索引 235：`mov w6, wzr` → `mov w6, #0x1`（`w6` 即第 6 参 `val3`）；其余已编译的跟踪函数 **IDENTICAL (strict)**；`multicast_owner_worker` / `multicast_waiter_worker` 在**两侧**均 STALE（5.15 目标未构建） |
| 冷启动 + `tools/gate_preflight.py` | **PREFLIGHT PASS**（5 项） |

`cmp_disasm` 的 `RESULT: FAIL` 属严格模式对本行**预期字面量差异**的报出，
符合 `AGENTS.md`「IDENTICAL (strict) **或已复核的注解差异**」中的后者，
已复核并归档。

## 结论与影响

1. **`val3` 确为阻塞点之一**，1 行改动即可改变 syscall 行为（35 → 11）。
2. **PI requeue 仍未成功**，失败点后移到 `EAGAIN`（无可 requeue waiter）。
   ⇒ **W1 竞态窗口此前从未建立、现在仍未建立。**
3. 因此「W1 从未真正工作」这一判断**依然成立**，只是原因比原假设更复杂：
   至少存在两个缺陷（比较值不匹配；`wait_futex` 上无可 requeue waiter）。
4. **对批次 D 的影响**：写入目标仍是一个从未成功 requeue 的空窗口，
   故批次 D **继续冻结**。

## 下一步（按证据排序）

1. **查 `FUTEX_WAIT_REQUEUE_PI` 的 park 语义**：`waiter_thread:48` 用它
   在 `wait_futex` 上阻塞。日志虽打印 `waiter parked`，但需确认
   waiter 是否真的挂在 `wait_futex` 的 waitqueue 上、
   以及 `FUTEX_CMP_REQUEUE_PI` 的 `nr_requeue=1` 是否与
   `race_route_wait_ms` 的超时相容。
2. **复核 `EDEADLK` 的成因**：既然基线是 `EDEADLK` 而非「无 waiter」，
   需确认是否 `owner` 在 waiter park 之前就持有了 `target_futex`
   （`threads.cpp:78` 早于 waiter 就绪），从而使 requeue 目标本就不可用。
3. 上述两项**须先出计划**再改（攻击关键路径）。批次 D 保持冻结。