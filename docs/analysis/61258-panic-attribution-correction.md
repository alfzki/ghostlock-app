# 6.12.58 panic 归因更正：panic 发生在 **GhostLock 自身**，且在 **PI-futex 路径**，与 `fd_graph` 无关

> 本文更正 `PROFILE-61258-01-20261003-fdgraph-fail.md` 的核心归因结论，
> 并给出批次 D 应当冻结的依据。证据全部来自已归档的 pstore 与本会话门禁。

## 1. 更正：panic 进程是 GhostLock，不是「无关进程」

原记录第 75/89 行称：

> 「panic 任务 `T14586` **不是 GhostLock**：本机 GhostLock 为 `T11660`」
> 「约 17 秒后**无关进程**遍历被污染的 rt_mutex waiter 链而 fault」

**pstore 不支持该结论。** 全文只有一个 `Comm:` 行：

```
[   61.638994][T14586] CPU: 0 UID: 10528 PID: 14586 Comm: libghostlock.so
    Tainted: P  W  O  6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k
```

- `Comm: libghostlock.so` ⇒ **T14586 就是 GhostLock 线程**。
- **`T11660` 在整份 pstore 中出现 0 次**，无从支持「本机 GhostLock 为 T11660」。
- 原记录很可能把「主线程 TID」与「worker 线程 TID」当成了两个进程。
  GhostLock 是多线程的（waiter / owner / consumer / pipe_worker），
  这些线程**同样名为 `libghostlock.so`**；oops 的 `PID:` 打印的是
  `current->pid`（即当前线程 TID），因此不同 TID 并不意味着不同进程。

⇒ panic 发生在 **GhostLock 自己**身上。

## 2. 崩溃点完全在 PI-futex waiter 拆除路径，无 epoll/pipe 帧

```
Call trace:
 rt_mutex_adjust_prio_chain+0x220/0x7c0
 remove_waiter+0x180/0x1ec
 rt_mutex_cleanup_proxy_lock+0x50/0x94
 futex_lock_pi+0x2b8/0x45c
__arm64_sys_futex+0x238/0x390
```

- `pstore` 中 `epoll|pipe_|anon_pipe` 匹配数 = **0**。
- 这条链是 `futex_lock_pi` **获取 PI 锁失败后回退**时走的清理路径：
  `rt_mutex_cleanup_proxy_lock → remove_waiter → rt_mutex_adjust_prio_chain`
  遍历 waiter 优先级链表时 fault：
  `Unable to handle kernel paging request at virtual address 0000000100000018`
  （`FSC=0x05 level 1 translation fault`，单次 fault、单次 Oops）。
- 寄存器中出现被截断的指针：`x22: 00000000ffffffc0`（高 32 位为 0），
  典型「poison 值当指针用」的形态。

⇒ **崩溃点是 W1 后端的 PI-futex 竞态，不是 route。**

## 3. 本会话门禁（`PROFILE-61258-02`）独立复现同一现象，且不写任何目标

冷启动 + 前置全 PASS（`tools/gate_preflight.py` 五项）下，
批次 A（**不写任何目标**）仍得到 `sys.boot.reason = kernel_panic`：

| 运行 | 冷启动 uptime | route 输出 | 结局 |
|---|---|---|---|
| #1 | 31 s | `RACE_SUMMARY … delivery=not-implemented` | 手动重启，终态未知（证据被我销毁） |
| #2 | 17 s | 与 #1 **逐字一致** | `kernel_panic` |

**空对照**（冷启动后静置 377 s，不跑 GhostLock）：
`bootreason=reboot,shell`，无 panic。

⇒ 三点合起来：

1. 手机自身稳定（空对照 PASS）；
2. GhostLock（**不写**）触发 panic；
3. 崩溃栈 100% PI-futex，**零** epoll/pipe 帧。

**结论：`fd_graph` 的写入与本次 panic 无因果关系；批次 D 即使全部实现，
也修不好这个 panic。**

## 4. 直接机理（与日志一致）

每次运行的日志都有：

```
[route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done
```

`errno=35` = `EAGAIN`。即 **PI-futex 重入/重排队失败并回退**，
而回退路径正是 `futex_lock_pi → rt_mutex_cleanup_proxy_lock →
remove_waiter → rt_mutex_adjust_prio_chain`。**崩溃发生在 W1 原语自身的
失败回退里**，与后续 route 做什么无关。

待区分的两个候选（都需要栈才能定案）：

- **(a)** 本项目的 PI 竞态在失败回退时**自身写坏了** waiter 链（例如
  `owner` 线程与 `waiter` 线程对同一 waiter 的并发 remove）；
- **(b)** 本项目更早的**页喷 / `prepare_kernel_page`** 污染了后续被
  `rt_mutex_adjust_prio_chain` 遍历到的链，`fd_graph` 无关但喷淋有关。

候选 (b) 与「批次 A 不写也崩」相容（喷淋在 route 之前执行）；
候选 (a) 同样相容。**二者都指向 W1 后端或喷淋，而非 route。**

## 5. 为什么此前整条路线对准了 `fd_graph`

| 步骤 | 当时的依据 | 更正后 |
|---|---|---|
| 假设 `splice()` 写入是元凶 | 该调用恒 `EBADF`，且成功分支解引用内核地址 | **删除是对的**（确为缺陷），但**不是 panic 原因** |
| 批次 A 作为「不写是否不崩」对照 | 用于归因 | **对照本身失败**：不写也崩 ⇒ 写入非必要条件 |
| 批次 D 实现 24,576 嵌套 epoll 投递 | 假设崩溃发生在 epoll/pipe 路径 | **栈中零 epoll/pipe 帧** ⇒ 该路径未被崩溃触及 |

⇒ 路线被「pstore 属于无关进程」这一**误判**带偏了。纠正它比继续推进批次 D 更重要。

## 6. 下一步（取代原批次 D 计划）

1. **取得批次 A 复现的栈**（当前最大缺口）。adb shell 为 `uid=2000`，
   KernelSU 未加载故无 `su`，`dmesg`（klogctl）与 `/sys/fs/pstore/` 均
   `Permission denied`，`/proc/last_kmsg` 不存在 ⇒ shell 下拿不到栈。
   需要用户侧提供一条 root 通道（Shizuku 即可，**不加载 KernelSU**，
   故不破坏门禁前置）。取得后归档为**诊断性**运行。
2. **对照复现 W1 失败回退**：用同一构建、只跑到 `CMP_REQUEUE_PI` 失败即止，
   不进 route，验证 panic 是否仍然发生。若发生 ⇒ 与 `fd_graph` 完全无关。
3. **审查 W1 PI 竞态的失败回退路径**（`race/pi_race.*` 与
   `session/backend/cve_2026_43499_backend.*`）：重点看 `owner`/`waiter`
   双线程对同一 `futex_waiter` 的 remove 是否缺少同步，以及
   `rt_mutex_cleanup_proxy_lock` 被触发时链是否已被本进程改写。
4. **批次 D 保持冻结**，直至 2/3 定位到 route 之外的真实成因。