# PROFILE-61258-03-20261003 — panic 归因**已证明**：GhostLock 自身 PI-futex 路径（复现成功）

- **日期**：2026-10-03
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：本分支 HEAD `85faf82`
- **触发方式**：CLI（`/data/local/tmp/ghostlock --load-prebuilt-profile`），**批次 A 不写任何目标**
- **原始证据**：`logs/gate-20261003-235401/PANIC_TRACE.txt`（4.2 MB，含完整 pstore）
- **复现对照**：`PROFILE-61258-01-20261003-fdgraph-fail`（App 启动，UID 10528）

## 结论

**panic 发生在 GhostLock 自身的 PI-futex waiter 拆除路径，且与 `fd_graph` route 无关。**
本次与门禁 `-01` 在**不同启动路径、同一构建**下产生**逐字节相同**的
fault 地址、调用栈与被破坏寄存器 ⇒ 满足 `AGENTS.md`「同构建复现」要求。

## 决定性证据

```
Unable to handle kernel paging request at virtual address 0000000100000018
Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP

CPU: 0 UID: 2000 PID: 23856 Comm: ghostlock
```

**faulting task 就是 GhostLock**（本次 UID 2000 CLI；门禁 -01 为 UID 10528
的 App）。这**证实**了 `61258-panic-attribution-correction.md` 的更正：
门禁 -01 原记录「panic 任务不是 GhostLock、本机 GhostLock 为 T11660」是错误的
——`T11660` 在 pstore 中出现 0 次，而唯一的 `Comm:` 行就是 GhostLock。

### 调用栈（与门禁 -01 偏移完全一致）

```
rt_mutex_adjust_prio_chain+0x220/0x7c0     ← fault 点
remove_waiter+0x180/0x1ec
rt_mutex_cleanup_proxy_lock+0x50/0x94
futex_lock_pi+0x2b8/0x45c
__arm64_sys_futex+0x238/0x390
invoke_syscall / do_el0_svc / el0_svc
```

| 项 | 本次（CLI, UID 2000） | 门禁 -01（App, UID 10528） |
|---|---|---|
| fault 地址 | `0x0000000100000018` | `0x0000000100000018` ✅ 同 |
| `pc` | `rt_mutex_adjust_prio_chain+0x220` | `+0x220` ✅ 同 |
| `lr` | `rt_mutex_adjust_prio_chain+0xf4` | `+0xf4` ✅ 同 |
| `x22` | `00000000ffffffc0` | `00000000ffffffc0` ✅ 同 |

`x22` 高 32 位为 0，是**被截断的 64 位内核指针**，形态与「被投毒的链表指针
当作 64 位值解引用」一致。`rt_mutex_adjust_prio_chain` 在遍历 waiter 优先级链表时
触发该解引用。

### 栈中无 epoll / pipe 帧

`epoll|pipe_|anon_pipe` 在本次 pstore 中匹配数为 **0**。
⇒ 崩溃路径**完全没有触及** `fd_graph` 的 epoll 图或管道机制。

## 取证方法（可复用）

本次不需要 root 通道，也不需要 Shizuku：

1. 冷启动 + `tools/gate_preflight.py` 五项 PASS；
2. 反复运行 GhostLock 直到 `sys.boot.reason=kernel_panic`
   （本次第 2 次命中，间歇率约 1/3，与 `KERNEL-PANIC-01` 描述一致）；
3. panic 重启后**立即**执行 `preload.so --pstore` —— 它以
   `dumpstatez` carrier 取得 uid 0 并 dump `/sys/fs/pstore/*`。

**关键约束**：必须用 `--pstore`，**不能用 `--full`**。
`--full` 含 `direct-map zero`，会把 SELinux 置为 permissive；而 GhostLock 的
W1 以 `check_selinux_off()` 为门槛，SELinux 已 permissive 时 **W1 整段被跳过**，
panicking 代码根本不会执行。

**另一关键约束**：`--pstore` 是**一次性**的（结束时 `STOP_SERVICE …
running_after=0`），root 不会留存。因此**顺序必须是先 GhostLock 崩溃、
重启后再读 pstore**，不能先取 root 再跑 GhostLock。

本次 `preload.so --pstore` 返回 `RESULT FAIL pstore_bootstrap uid0=1
context=dumpstate selinux=Enforcing direct_map_used=0 absolute_kernel_write=0`
—— 即取到了 uid 0、**未翻转 SELinux**、**未做内核写**，但其内部的 pstore
捕获子步骤判 FAIL（`pstore_files=1`，`/sys/fs/pstore` 下只有
`console-ramoops-0`，无 dmesg zone）。尽管判 FAIL，**捕获内容完整可用**。

## 附带发现：`fd_graph` 投递原语在本机可用

`preload.so` 自身在 ramoops 中留下**两次不同**的成功记录：

| 来源 | page | reclaim/chain/bit4 |
|---|---|---|
| `preload-full-log.txt`（用户历史） | `0xffffff82fdfc0000` | 2 / 2 / 1 |
| 本次 ramoops 归档 | `0xffffff82fda40000` | 3 / 3 / 1 |

`RESULT PASS pipe_flags_candidate … fake_count=16 … bit4_hits=1` ⇒
§2.18.2 描述的 `chain_hit` + `bit4` 判据在本机**确实能命中**，
批次 D 要移植的投递机制本身是可行的。

⇒ 因此「panic」与「`fd_graph` 能否工作」是**两个独立问题**。

## 下一步（取代冻结的批次 D）

崩溃点已定位到 W1 的 PI-futex 竞态，**不在 route**。批次 D 继续冻结。

1. **审查 W1 失败回退**：`src/core/race/threads.cpp:182` 的
   `FUTEX_CMP_REQUEUE_PI` 在 `errno=35`(`EAGAIN`) 时回退，
   而回退路径正是 `rt_mutex_cleanup_proxy_lock → remove_waiter`。
   重点确认 `owner`/`waiter` 两线程是否可能对同一 `futex_waiter`
   并发 remove，以及本项目是否在回退前改写了 waiter 链。
2. **区分候选 (a)/(b)**：
   (a) PI 竞态自身写坏 waiter 链；
   (b) 更早的页喷 / `prepare_kernel_page` 污染了随后被
   `rt_mutex_adjust_prio_chain` 遍历到的链。
   两者都与「批次 A 不写也崩」相容，需逐段开关二分（每段冷启动 + 前置 PASS）。
3. `0x100000018` 的来源待解释：低字节 `0x18` 与 profile 中 `pipe_flags`
   偏移相同，是否为巧合需确认。