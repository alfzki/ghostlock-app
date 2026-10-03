# W1 PI-futex requeue 比较值修正计划（2026-10-04）

## 现状与基线

- **分支 / commit**：`main`，基线 `9627c00`（`docs(61258): W1 review finds a requeue comparison that can never match`）
- **基线二进制**：`build/native/ghostlock`，sha256 `b5825b42fab08c22e98e78df6faa52b0b5236679647a0b6267f27c4e4a4a2e1e`
- **当前行为**：`race/threads.cpp:182` 的 `FUTEX_CMP_REQUEUE_PI` 在**全部真机运行**中
  均返回 `ret=-1 errno=35`（**`EDEADLK`**，非 `EAGAIN`），即 PI requeue 从未成功。
- **已知问题**：`support::futex_op`（`support/util.cpp:156`）是 `SYS_futex` 的直通包装，
  故下述调用的 `val=1`、`val3=0` 直接进入原始 syscall。内核
  `futex_requeue(..., nr_wake=val, nr_requeue=timeout, uaddr1=&val3)` 判定
  `if (uval != nr_wake) goto out_unpush;`，即 `0 != 1` ⇒ 恒 `EAGAIN`。
- **栈证据**：`PROFILE-61258-03` —— `rt_mutex_adjust_prio_chain+0x220` ← `remove_waiter`
  ← `rt_mutex_cleanup_proxy_lock` ← `futex_lock_pi`，两次不同启动路径逐字节一致。
- **审查依据**：`docs/analysis/w1-pi-race-review.md`。

## 目标与约束

**目标**：判定 `FUTEX_CMP_REQUEUE_PI` 的比较值是否确为「恒失败」，
即 **1 行改动 + 1 次真机门禁**即可证实或推翻 §2 的假设。

**非目标（本批明确不做）**：

- 不实现批次 D（24,576 嵌套 epoll 投递）—— 仍冻结。
- 不修改 `fd_graph_route.cpp`、不改 profile / wire 格式。
- 不改「no waiter」候选路径（若本实验显示 `errno` 仍为 35，转入该方向另出计划）。
- 不动 `race/threads.cpp` 中任何其他行。
- 不为「让门禁通过」而调参；本实验**预期可能 FAIL**，FAIL 与 PASS 同等归档。

**约束**：攻击关键路径 ⇒ 须 `cmp_disasm` + 冷启动真机门禁 + 归档。

## 改动清单

| 文件 | 改动 | 理由 |
|---|---|---|
| `src/core/race/threads.cpp:184` | 末位实参 `0` → `1`（`val3`） | 使 `uval == nr_wake`，解除必然 `EAGAIN` |

改动共 **1 个字面量**，不触碰控制流、线程结构或所有权。

> 注：`PiRace::run()` 无独立符号，被内联进
> `run_main_route_threads`（`threads.cpp:218` 调用 `race.run()`），
> 而后者在 `tools/cmp_disasm.py` 的 `TARGETS` 内 ⇒ **本改动被反汇编门禁覆盖**。

## 数据流/控制流差异

**新旧对照（仅 syscall 第 6 参）**：

```c
// 旧
futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &target_futex, 0);
//                                                        ↑val3=0   ⇒ uval(0) != nr_wake(1) ⇒ EAGAIN
// 新
futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &target_futex, 1);
//                                                        ↑val3=1   ⇒ uval(1) == nr_wake(1) ⇒ 可继续
```

**不变量**：

1. `uaddr`、`op`、`val`、`nr_requeue`、`requeue_pi`（`&target_futex`）**全部不变**；
2. 仅解除比较失败这一早退分支，**不新增**任何 syscall 或线程动作；
3. wait-queue 的建立（`waiter_thread` 的 `FUTEX_WAIT_REQUEUE_PI`，行 48）
   与 owner 的加锁顺序（行 78/90）**不变**；
4. 因此这是**最小可证伪实验**：若 `errno` 改变，则假设成立；
   若不变，则排除该假设且不引入任何新行为。

## 兼容性与回滚

- **wire / profile**：无变化（`sha256 550d1b0f…` 不变）。
- **回滚**：`git revert` 单 commit 即可，无迁移、无持久化状态。
- **风险**：若假设成立，PI requeue 将**首次真正生效**，竞态窗口会被建立。
  这是预期内的行为变化，但意味着**此前从未跑过的代码路径会被执行**。
  故本实验按攻击路径对待：冷启动、单 route、`tools/gate_preflight.py` 前置全 PASS。

## 验证矩阵

| 批次 | 命令 / 动作 | 预期结果 |
|---|---|---|
| 1 | `make -C src native-host-tests` | exit 0 |
| 2 | `make -C src ghostlock` | exit 0，**0 warning** |
| 3 | `make -C src lint-tidy` | exit 0，**0 finding** |
| 4 | `./gradlew :app:testDebugUnitTest :profile-core:test` | exit 0 |
| 5 | `python3 tools/cmp_disasm.py <baseline> build/native/ghostlock` | `run_main_route_threads` 仅出现**已复核的字面量差异**（`0`→`1`）；其余 7 个攻击函数 **IDENTICAL (strict)** |
| 6 | 冷启动 + `tools/gate_preflight.py` | **PREFLIGHT PASS**（5 项） |
| 7 | 推送 `ghostlock` + `profile.bin`，冷启动运行 1 次 | 日志 `CMP_REQUEUE_PI ret=… errno=…`；**判读 `errno` 是否仍为 35** |
| 8 | 归档门禁记录 | PASS/FAIL 同等归档至 `docs/analysis/device-gates/` |

**判读规则（先定好，避免事后解释）**：

- `errno != 35` ⇒ 假设**证实**，PI requeue 恒失败成立，W1 竞态此前从未建立。
- `errno == 35` ⇒ 假设**证伪**，转入「`wait_futex` 上无可 requeue waiter」方向。
- 出现 panic ⇒ 记录栈并归档；`PROFILE-61258-03` 已提供同类栈基线可比对。

## 明确保留

- `threads.cpp:57-67` 的 ghost disarm（multicast 专用，fd_graph 不执行）—— **不动**。
- `threads.cpp:137` 消费者的 `FUTEX_LOCK_PI` fallback —— **不动**。
  它是 `PROFILE-61258-03` 栈上的实际 fault 源，但修复它属另一批次；
  本实验只判定 requeue 是否曾成功，避免同时改两处而无法归因。
- `threads.cpp:187` 的 `TODO(pi-timeout-01)`（`route_done` 无上限）—— **不动**。
  已观测到挂起，但与本实验正交。
- `waiter_thread` / `owner_thread` / `consumer_thread` 的时序 —— **不动**。

## 进度

- [x] 取证：确认 `futex_op` 为直通包装，`val3=0` 与 `nr_wake=1` 恒不匹配
- [x] 确认 `cmp_disasm` 覆盖该改动（内联进 `run_main_route_threads`）
- [x] 保存基线二进制 `b5825b42…`
- [x] 实施 1 字改动（`val3: 0 → 1`）
- [x] 批次 1-4 门槛：host 21 suites / NDK 0 warning / lint 0 / gradle 0
- [x] 批次 5 `cmp_disasm`：1/413 指令（idx 235，`mov w6, wzr` → `mov w6, #0x1`），
      其余跟踪函数 IDENTICAL (strict)
- [x] 批次 6-7 冷启动真机门禁：**PREFLIGHT PASS**；`errno` 由 `35` 变为 `11`
- [x] 批次 8 归档：`PROFILE-61258-04-20261004-w1-val3-experiment-PASS.md`

### 实验判定

按本计划「判读规则」：

- `errno != 35` ⇒ 假设**证实**「`val3` 是阻塞点」；
- 但 requeue **仍未成功**（现为 `EAGAIN`，无可 requeue waiter）⇒ **部分证实**，
  且暴露出**第二个独立缺陷**。

**并更正一处既有错误**：`errno=35` 是 **`EDEADLK`**，不是 `EAGAIN`
（`EAGAIN=11`、`EDEADLK=35`，见 NDK `asm-generic/errno*.h`）。
代码中从未出现 `EAGAIN`，原解释属误读。因此对 `EDEADLK` 成因的解释
**并不完整**，需按 `PROFILE-61258-04` 的「下一步」另查。