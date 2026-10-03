# W1 PI-futex 竞态审查：崩溃路径与一个必然失败的 requeue 比较

> 依据 `PROFILE-61258-03` 捕获的栈（`rt_mutex_adjust_prio_chain+0x220`
> ← `remove_waiter` ← `rt_mutex_cleanup_proxy_lock` ← `futex_lock_pi`）。
> 本文是代码审查结论，**尚未经真机验证**，末尾给出最小验证实验。

## 1. 崩溃点定位

栈显示 fault 发生在 `futex_lock_pi` 的**失败回退**路径：

```
futex_lock_pi
  └─ rt_mutex_cleanup_proxy_lock      ← PI 获取失败，撤销 waiter
      └─ remove_waiter
          └─ rt_mutex_adjust_prio_chain+0x220   ← 遍历 waiter 优先级链表时 fault
```

`x22 = 0x00000000ffffffc0`（高 32 位为 0，64 位指针被截断），
fault 地址 `0x100000018`（低字节 `0x18`）。两次不同启动路径完全一致。

### 哪个 `FUTEX_LOCK_PI`

本仓库共有 4 处 `FUTEX_LOCK_PI`（`race/threads.cpp`）：

| 行 | 对象 | 是否可能是本次 fault 源 |
|---|---|---|
| 24 | `chain_futex` | 否：waiter 先加 `chain`，owner 在 waiter 就绪后才加（行 90），无竞争 |
| 65 | `dummy_pi`（栈地址） | **否**：`route_needs_ghost_disarm()` 仅对 multicast 为真，测试 `route_policy_test.cpp:115` 断言 fd_graph/select/tcp 均为假 ⇒ 该分支不执行 |
| 78/90 | `target_futex` / `chain_futex` | 否：owner 在竞态窗口外，且行 90 之前未与 waiter 竞争 `chain` |
| **137** | **`target_futex`（50 ms 超时）** | **是** |

行 137 位于 `consumer_thread` 的 fallback：当 `sched_setattr_tid()` 失败时，
消费者对 **`target_futex`**（waiter 被 requeue 的目标锁）发起
`FUTEX_LOCK_PI`，超时 50 ms。超时即走
`rt_mutex_cleanup_proxy_lock → remove_waiter`，
与栈完全吻合。

## 2. 一个**必然失败**的 requeue 比较（高度可疑）

`race/threads.cpp:182`：

```c
long rq = support::futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1,
                            reinterpret_cast<void *>(1), &target_futex, 0);
```

`support::futex_op`（`support/util.cpp:156`）是**直通包装**：

```c
return syscall(SYS_futex, uaddr, op, val, timeout_or_value, uaddr2, val3);
```

故原始 syscall 参数为 `val=1`、`val3=0`。内核
`futex_requeue(uaddr, flags, uaddr2=requeue_pi, nr_wake=val, nr_requeue=timeout, uaddr1=&val3)`
的判定是：

```c
if (uval != nr_wake)   /* uval 来自 val3 */
    goto out_unpush;   /* → -EAGAIN */
```

即 `0 != 1` ⇒ **每次调用都必然返回 `EAGAIN`**。
而全部真机日志无一例外都是 `CMP_REQUEUE_PI ret=-1 errno=35`（`EAGAIN`）。

**若成立，PI requeue 从未成功过**，竞态窗口根本没有建立，
`target_futex` 上不会存在被 requeue 的 waiter。

### 必须声明的不确定性

`EAGAIN` 有两个来源：比较失败，**或** `wait_futex` 上没有可 requeue 的 waiter。
日志确实先打印了 `[route] waiter parked; owner started`，
说明 waiter 已 park，因此「比较失败」是更可能的解释，**但仅凭 `errno` 无法排除第二种**。

### 最小验证实验（1 行改动）

把 `val3` 由 `0` 改为 `1`（令 `uval == nr_wake`），重建、真机冷启动跑一次：

- 若 `errno` **不再是 35** ⇒ 本条**证实**；
- 若仍是 35 ⇒ 说明真正原因是「无 waiter」，需另查 waiter 的 park 语义
  （`FUTEX_WAIT_REQUEUE_PI` 是否真的落在 `wait_futex` 上）。

⚠️ 该改动触及攻击关键路径，按 `AGENTS.md` 需计划文档 + `cmp_disasm`
+ 真机门禁。**本记录不预先实施。**

## 3. 与「喷淋污染」的关系（候选 b）

即便 requeue 恒失败，消费者行 137 的 `FUTEX_LOCK_PI` 仍会**反复**
在 `target_futex` 上建立/撤销 PI waiter（`select_consumer_burst_calls` 次/轮），
每次撤销都走 `remove_waiter → rt_mutex_adjust_prio_chain` 遍历链表。

`futex_waiter` 位于**线程栈**上；若 `prepare_kernel_page` 的页喷在该窗口内
回收了该栈页，则链表中的 waiter 指针指向已回收内存，
`rt_mutex_adjust_prio_chain` 遍历即 fault —— 与
`threads.cpp:57-61` 注释自己担心的
「`remove_waiter()` 留下的 `pi_blocked_on` 指向**已回收**的 waiter」一致。

⇒ 故 **候选 (b)（喷淋污染被遍历的链）仍然成立**，且与「批次 A 不写也崩」相容。

## 4. 结论与优先级

1. **已证明**：崩溃在 GhostLock 自身 PI-futex 撤销路径，不在 `fd_graph`
   （栈中零 epoll/pipe 帧；两次启动路径逐字节一致）。
2. **高度可疑（待 1 行实验确认）**：`CMP_REQUEUE_PI` 的 `val3=0` 与
   `nr_wake=1` 不匹配，导致 requeue 恒失败。若成立，W1 竞态**从未真正建立**，
   这是比批次 D 更上游、更根本的问题。
3. **待区分**：`remove_waiter` 遍历时链表是否被页喷污染（候选 b）。

建议顺序：**先做 §2 的一行实验**。若 requeue 恒失败成立，则 W1 竞态本身
从未工作，崩溃只是「反复建/撤 PI waiter + 页喷」的副作用，
修好 requeue 后再评估崩溃是否消失；此时 `fd_graph` 的优先级应重新评估。