# PROFILE-61258-02-20261003 — batch A 无写入对照：**INCONCLUSIVE**（间歇 panic）

> ## ⚠️ 结论已从 FAIL 下调为 INCONCLUSIVE（2026-10-03 晚）
>
> **本记录初版判定为 FAIL，依据是 4 次运行中 1 次 panic。补测表明 panic 是
> 间歇性的，FAIL 判定不成立。** 详见本文末「补测：锁屏状态不是决定变量」。
> 保留初版原文与全部证据，未改写。

## 结论（以补测后为准：INCONCLUSIVE）

**批次 A 未向任何目标写入；4 次运行中 1 次 `kernel_panic`，3 次正常。**
同构建、同 profile、同 route 终点（`RACE_SUMMARY … pipe_fill_hits=10`），
结果不一致 ⇒ **panic 为间歇性**，符合 `AGENTS.md` `KERNEL-PANIC-01`
「同构建可 PASS/panic/PASS」的描述。

**因此批次 A 既不是「安全」的证明，也不是「崩溃」的证明**：
它未能充当干净对照，`fd_graph` 是否为成因**仍未定案**。
- **设备**：`10AFAL1TD7002HB`（vivo V2514，X300 Pro）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`（与 profile **精确匹配**）
- **route**：`fd_graph`（单 route）
- **构建**：本分支 HEAD `6fa2bc5`
- **二进制**：`build/native/ghostlock`（757248 B）
- **profile**：GLK1 v2，2226 B，sha256 `550d1b0f4057a404f84e5233d12e96d14926d879f1b400b7c35ddd0258e76d4b`
- **原始证据**：`logs/gate-20261003-222605/`（stdout×2、bootreason、binary.sha256、build_commit、profile.bin）

## 结论（先说结果）

**FAIL。批次 A 未向任何目标写入，仍导致 `kernel_panic`。**

这**推翻了**「原 panic 由 `fd_graph` 写入引起」的假设：
**写入不是 panic 的必要条件。** 对象扰动（kernelsnitch 碰撞扫描 / 页喷 /
`prepare_kernel_page`）或挂起本身即足以触发内核 panic。

## 门禁前置条件（本次全部通过，且为首次逐项验证）

`tools/gate_preflight.py`（本会话新增，`6fa2bc5` 修复 `nofile` 读取）：

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | 运行时 uptime 17 s / 31 s |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |

> 首次门禁 `PROFILE-61258-01` 失败的原因正是这些前置条件未核验
> （`boot_ms=42853` 非冷启动、KernelSU 状态未记录），导致 panic 无法归因。
> 本次前置条件齐备，故结论可归因。

## 运行记录

### 运行 #1 — **不确定（证据被我自己的重启销毁）**

- 冷启动 uptime 31 s，前置 PASS。
- route 正常跑完：`RACE_SUMMARY tries=10 pipe_fill_hits=10 chain_hits=0 bit4_hits=0 delivery=not-implemented target=ffffff80027c6960`
- 进程**挂起**，`timeout 300` 击杀 → exit `124`。
- +325 s 时设备仍存活。
- **随后我为运行 #2 手动 `adb reboot`，运行 #1 的终态因此不可知。**

### 运行 #2 — **kernel_panic（决定性）**

- 冷启动 uptime 17 s，前置 PASS。
- route 输出与 #1 **逐字一致**（同一构建、同一 profile）。
- 同样挂起，`timeout 180` 击杀 → exit `124`。
- +214 s 仍存活；其后**设备 panic 并重启**。
- **决定性证据**：`sys.boot.reason = kernel_panic`、`ro.boot.bootreason = kernel_panic`。
- 重启后 SELinux `enforce=1`（批次 A 不写 W1，此为**预期值**，非异常）。

## 证据可得性限制（影响归因深度，非本次结论的成立条件）

adb shell 为 `uid=2000(shell)`，且 KernelSU 未加载（无 `su`），因此：

| 证据源 | 状态 |
|---|---|
| `dmesg` | **Permission denied**（`klogctl`） |
| `/proc/last_kmsg` | **不存在**（该内核未提供） |
| `/sys/fs/pstore/` | 已挂载 `rw`，但 **Permission denied** |
| `su` | 不存在 |

⇒ **无法取得 panic 调用栈。** 本记录只断言「发生了 kernel_panic」（由
`boot.reason` 权威给出），**不断言具体panic 位置**。

## 过程中我自己的两处误读（记录以免重复）

1. **误把 `pstore` 读不到当成「pstore 为空」。**
   早前输出 `pstore entries: 0` 实为 **Permission denied**（glob 无匹配）。
   由此我一度宣称「无既有 panic、pstore 干净」——该结论**不成立**，已撤回。
2. **误把 adb `error: closed` 当作连接抖动。**
   实为设备在 panic 过程中掉线。曾据此在 +356 s / +214 s 两次宣称「无 panic」，
   该结论**错误**。真正判据是 `sys.boot.reason`，而非「设备还能应答」。

## 附带发现（非本门禁判定项）

1. **进程挂起而非退出**：route 返回 `ROUTE_RETRYABLE` 后，进程未退出，
   两次均需 `timeout` 强杀（exit `124`）。日志停在
   `[route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done`。
   属生命周期缺陷，与 panic 独立，需单独定位。
2. **后端 W1 原语本轮失败**：`CMP_REQUEUE_PI ret=-1 errno=35`（`EAGAIN`）。
   即便 route 完整可用，本轮 W1 也不会完成。
3. **批次 A 日志改造已验证生效**：`delay_us` 逐档、`pipe_fill` 如实反映
   `vmsplice` 返回 8、`delivery=not-implemented`、`target=ffffff80027c6960`
   （与 `preload.so` 成功日志的目标地址逐字一致）。

## 下一步（结论已改变优先级）

原计划是「先跑批次 A 证明不写不崩，再实现批次 D」。**该计划的前提已被本门禁证伪。**

在 panic 归因到具体阶段之前**不应**实现批次 D——因为若扰动本身即致命，
叠加 24,576 个 epoll 的建图只会让现象更早、更剧烈地复现。

建议顺序：

1. **取得 panic 栈**（当前最大缺口）。需要 root 才能读 `pstore`/`dmesg`：
   - 用 KernelSU/其他已 root 的通道读取 `/sys/fs/pstore/*`（**注意**：这会使
     「KernelSU 未加载」前置失效，需在记录中声明该次为**诊断性**运行，不作门禁判定）；
   - 或在设备侧启用可读 `klogd`/`pstore` 后重跑。
2. **二分定位 panic 阶段**：当前候选为
   (a) `prepare_kernel_page` 页喷；(b) kernelsnitch 碰撞扫描；(c) route 挂起后的线程 teardown。
   可用「只跑 spray 不进 route」「只建管道不喷」等**逐段开关**二分，
   每一段仍需冷启动 + 前置 PASS。
3. 归因前**冻结批次 D 实现**。
---

## 补测：锁屏状态不是决定变量（本记录由 FAIL 下调为 INCONCLUSIVE 的依据）

### 起因：门禁协议漏掉了锁屏/休眠状态

初版两次运行（#1/#2）**均未记录锁屏与唤醒状态**，这是协议缺陷。
本机 `screen_off_timeout=30000`（30 s），而运行分别持续 300 s / 180 s，
因此**两次运行中设备大部分时间处于息屏/锁屏状态**。vivo 的后台冻结器
（pstore 中可见 `vivo_bgc_binder_frozen_callback … freeze 18786`）
会在息屏后冻结后台进程，与 PI-futex waiter 的交互是该场景下的合理怀疑点。

### 受控对照

| 运行 | 屏幕状态（已核验） | 启动 uptime | 超时 | 结果 |
|---|---|---|---|---|
| #1 | **未记录**（协议缺陷） | 31 s | 300 s | 未知（被我手动重启销毁证据） |
| #2 | **未记录**（屏幕约 30 s 后息屏） | 17 s | 180 s | **kernel_panic** |
| #3 | **Awake + 已解锁**（`KeyguardShowing=false`，timeout 改 1800000，`stayon true`） | 72 s | 200 s | 正常（+412 s uptime，`bootreason=reboot,shell`） |
| #4 | **锁屏/息屏**（timeout 恢复 30000，`stayon false`，运行期间息屏） | 17 s | 200 s | 正常（+337 s uptime，`bootreason=reboot,shell`） |

四次运行的 route 终点**完全一致**：`RACE_SUMMARY tries=10 pipe_fill_hits=10
chain_hits=0 bit4_hits=0 delivery=not-implemented target=ffffff80027c6960`。

### 结论

**运行 #4 锁屏/息屏却未 panic**，因此**锁屏状态不是决定变量**，
「panic 由锁屏引起」这一假设**被证伪**。真实情况是
**同构建下 panic 间歇发生（已知 3 次运行中 1 次）**。

⇒ 因此本门禁**不能**判定批次 A 为 FAIL，也不能判定其为 PASS。

### 我在此过程中的两次过度断言（均已被后续证据推翻，记录以免重复）

1. 初版称「批次 A 触发 panic」——由 1 次 panic 推广到确定性结论，
   未先确认可复现性。补测显示为间歇。
2. 随后称「锁屏状态是决定变量」——由 #3（唤醒解锁）未panic 推广，
   但 #4（锁屏）同样未 panic，**该断言错误**。

### 仍然成立的部分

崩溃栈证据与间歇性无关，仍然有效：
`PROFILE-61258-01` 的 pstore 显示 panic 发生在 **GhostLock 自身线程**
（`PID: 14586 Comm: libghostlock.so`），且栈 **100% 位于 PI-futex 路径**
（`futex_lock_pi → rt_mutex_cleanup_proxy_lock → remove_waiter →
rt_mutex_adjust_prio_chain`），**零** epoll/pipe 帧。
该结论见 `docs/analysis/61258-panic-attribution-correction.md`，不受本次下调影响。
