# `fd_graph` 写入原语实施计划（批次 8，L 级，待评审）

**状态：待用户评审。评审通过前不得改动攻击关键路径代码。**

依据：`docs/analysis/fd-graph-primitive-scoping.md`（含指令级证据分级）
门禁证据：`docs/analysis/device-gates/PROFILE-61258-01-20261003-fdgraph-fail.md`

## 1. 动机

6.12.58 profile 侧已确认无缺陷（物理地址对与 12 个几何常量均在真机验证命中），
阻塞点全部集中在 `src/core/route/fd_graph_route.cpp` 的写入原语。首次真机门禁
`chain_hits=0` 并引发 kernel_panic，因此 6.12.58 目前不可用。

目标：把 stub 换成 `preload.so` 证实的 **pipe_buffer 槽位回收 + 受控页写入**机制，
使 W1 能完成，并让成功判定不再依赖自读回。

### 1.1 为什么必须是 fd_graph（三条 route 的现状）

复核结论（2026-10-03）：6.12.58 上**其余三条 route 均已排除**，
fd_graph 不是偏好选择而是唯一候选，因此本 port 无法绕开。

| route | 状态 | 依据 |
|---|---|---|
| `select_stack` | **已证不可行** | 见下 |
| `tcp_zerocopy` | **机制未确认，阻塞** | 见下 |
| `multicast_waiter` | 不支持 | 仅 5.x |

**`select_stack` 不可行**（`tcp-zerocopy-6x-plan.md:19-59`，基于本机 `boot.img`
逐字节反汇编，非推测）：
- 实测 `waiter_shift = 14`（pselect 链 592B − futex 链 576B → Δ112B → 14 qword）；
- 路由可寻址窗口 `global_word ∈ [0,14]`（`PSELECT_ROUTE_NFDS=320` ⇒
  `words_per_set=5`）；
- waiter 需要落在 `[14,27]`；
- 窗口无法扩大：`core_sys_select` 仅在 `round_down(FDS_BYTES(nfds),8) < 43`
  时把 `fd_set` 放内核栈，`nfds=321` 即落到堆，永远无法与栈上 waiter 重叠；
- `[14,27] ∩ [0,14]` 为空。
- 且该结论有**真机代价**：文档记载此前 select_stack 在本内核已导致 **3 次 kernel panic**。
  该结论另有公开 PoC 独立佐证（`tcp-zerocopy-6x-plan.md:379-385`）。

**`tcp_zerocopy` 阻塞**（同文档 §批次 3' 决策门）：
- 批次 1 只证明原语存在、偏移可真实植入用户缓冲区，**未证明**写落点正确；
- 路由把 `waiter_task`/`fake_lock` 写到 `zc[0x28]`/`zc[0x30]`，那是 **6.1 compact 家族**
  布局；本内核 waiter 为 non-compact（`task@0x50`/`lock@0x58`），对不上；
- 硬阻塞：伪造 waiter 由 `prepare_skb_payload` 写入 `heap.current.base`，
  而 zc 的写入目标是 `mapping + page_size`，**不是同一块内存**；
  「谁把哪块内存变成 PI walk 实际走到的 waiter」在本仓库与 git 历史中**均无记载**。
- 用户已明确要求「路线跑通前不碰真机」，故不得试验性真机验证。

**关键结论：tcp_zerocopy 的阻塞点与 fd_graph 的缺口是同一个问题** ——
「写入如何落到内核真正遍历的那个对象上」。`preload.so` 正是这一问题的**已验证答案**
（同机同 kernel `RESULT PASS`），因此 fd_graph 的 port 必须把机制补全，
而不是绕道另选 route。

> 文档漂移（待修）：`tcp-zerocopy-6x-plan.md:195-196` 写「故 profile 保持
> `select_stack`（`waiter_shift = 0`）」，但该 profile 已在 `aed09ad` 改为 `fd_graph`，
> 现无 `select_stack` 块也无 `compact_waiter`。结论本身仍有效（select_stack 不可行），
> 只是「保持 select_stack」的表述已过时。

### 1.2 已解决的部分与真正的缺口

把「写什么」与「怎么送到」分开看，batch D 的范围会小得多：

**已解决且已验证 —— 写什么。** non-compact waiter 几何已在代码库内且双源核对
（`src/core/kernel/target.h:77-85`，并由 `ghostlock-extract boot.img --analysis`
对本镜像独立输出同一组值）：

```
FAKE_WAITER_TREE_PRIO_OFF   = 0x18      FAKE_WAITER_PI_TREE_PRIO_OFF     = 0x40
FAKE_WAITER_TREE_DEADLINE_OFF = 0x20    FAKE_WAITER_PI_TREE_DEADLINE_OFF = 0x48
FAKE_WAITER_PI_TREE_ENTRY_OFF = 0x28    FAKE_WAITER_TASK_OFF             = 0x50
FAKE_WAITER_LOCK_OFF        = 0x58      FAKE_WAITER_WAKE_STATE_OFF       = 0x60
                                           FAKE_WAITER_WW_CTX_OFF         = 0x68
```

且崩溃证据指向的正是这个结构：首次门禁的 pstore 调用栈为
`futex_lock_pi → remove_waiter → rt_mutex_cleanup_proxy_lock → rt_mutex_adjust_prio_chain`，
即内核正在遍历 **rt_mutex PI waiter** 链时被破坏。
换言之，**要写的目标结构是已知的、已验证的，且崩溃本身印证了它。**

**真正的缺口 —— 怎么送到。** 唯一未解决的是「如何把写落到 PI walk 实际遍历到的
那个 waiter 上」：
- `select_stack` 送不到（窗口 `[0,14]` 与所需 `[14,27]` 不交）；
- `tcp_zerocopy` 送不到（写 `heap.current.base`，而 zc 目标是 `mapping + page_size`）；
- `fd_graph` 送不到（stub 把内核地址当 fd，恒 `EBADF`）；
- `preload.so` **送得到**（同机同 kernel PASS）。

因此 batch D 的本质不是「发明一种新原语」，而是**把 preload.so 已验证的投递路径
（epoll fd 图 + `pipe_buffer` `CAN_MERGE` + 命令字驱动的 `write`）移植过来**，
落点沿用上面已验证的 waiter 常量。这与 §1.1 的结论一致：
三条旧 route 与 fd_graph 卡在同一个问题上，而答案就在 preload.so 里。

## 2. 影响文件

| 文件 | 改动性质 |
|---|---|
| `src/core/route/fd_graph_route.cpp` | 重写 `execute()`；新增 `pipe_worker` 线程与槽位状态 |
| `src/core/route/fd_graph_route.h` | 新增成员（worker 句柄、槽位、哨兵、统计） |
| `src/core/profile/model.h` | `FdGraphLayout` 增 4 个 `optional<uint32_t>` |
| `src/core/profile/binary.cpp` | 字段表增 4 项（**顺序须与 Kotlin 一致**） |
| `app/.../data/route/FdGraphConfig.kt` | `entries()`/`apply()`/`from()` 同步 4 键 |
| `app/src/main/assets/kernel_profiles/6.12.58-*.conf` | 填 4 个新字段值 |
| `app/src/test/resources/native-doc-golden.sha256` | 导出字节变化后同步 |
| `docs/kernel_profiles/PROFILE_SCHEMA.md` | 记录新字段语义 |
| 新增 native host 测试 | 几何往返 + 计数器语义 + 生命周期 |

## 3. 分批实施（每批独立过门槛，前一批不过不进下一批）

### 批次 A：移除无效与错误代码（**低风险，建议先做**）

1. 删掉 `fd_graph_route.cpp:264` 的 `splice(..., static_cast<int>(target), ...)`
   —— 内核地址截断成 `0x27c6960` 恒 `EBADF`，是死代码。
2. 修 `collision_page`（`:208`）：`ks->collisions` 是 `size_t` **计数**
   （`kernelsnitch.h:84`），不可当地址。改为真实碰撞页来源，或删除该日志。
3. 修 `reclaim_hits++`（`:277`）语义：现统计「vmsplice 返回 8」，与
   `preload.so` 的 `RECLAIM_HIT` 不同名，避免日志误导。
4. `RACE_SUMMARY` 补 `delay_us` 字段，否则无法定位命中档位。

**理由**：这批不改机制，但去掉了一个恒失败的调用与一处类型误用。
由于 panic 发生在 route 扰动共享对象之后，**移除无效写入有可能直接降低崩溃面**，
且能在下一次门禁中验证「不写是否就不崩」这一关键对照。

### 批次 B：profile 几何扩展（L 级 wire 变更，双侧同步）

新增 `gen`(0xa8) / `refs`(0xb0) / `depth`(0xb8) / `refcount`(0xbc)，
供独立验证用。必须同步 native `binary.cpp` 与 Kotlin `FdGraphConfig`（键名逐字一致、
顺序一致），并更新 golden 哈希。

**前置**：先确认这 4 个偏移确为 6.12.58 的 `eventpoll`/`epitem` 字段偏移
（`preload.so` 串给出 `gen=0xa8 refs=0xb0 depth=0xb8 refcount=0xbc`，
但那是**通用值**，需 BTF 或真机读回交叉验证）。

### 批次 C：补齐机制证据（只读分析，零代码风险）

反汇编 `preload.so` 的编排函数，把 scoping §2.3 的推断升级为指令级事实。

**已确认**（scoping §2.4）：全部五个阶段格式串落在**单个** 8356 字节函数
`0x2205a8`；其 syscall 清单为 `epoll_ctl`×7、`read`×2、`write`×1，
**`splice`/`vmsplice`/`tee` 各 0 次**。故：原语是 **epoll fd 图**
（7 次 `epoll_ctl` 操纵 `epitem.fllink`），payload 经**单次 `write`** 投递。

**待确认**：

1. ~~7 次 `epoll_ctl` 的参数序列~~ → **已确认**（scoping §2.5.1）：6×`EPOLL_CTL_ADD`
   把同一目标 fd 注册进多个 epoll 实例以拉出 `epitem.fllink` 宽图，
   1×`EPOLL_CTL_DEL(event=NULL)` 摘链（即 `decoy_unlink`）。
2. ~~单次 `write` 的目标 fd~~ → **已确认**（§2.5.2）：`write(fd_table[4], buf, count)`，
   是**普通 fd**；且由命令字驱动（`read(fd,&c,1)`，`c=='W'` 才写）。
3. **部分确认**（§2.5.4）：编排函数含 `getrlimit`×6 / `setrlimit`×4
   → 抬 `RLIMIT_NOFILE` 取得 fd 额度；配合日志里的 `fds=1964` / `fds=1005`，
   说明「fd graph」是**批量开 fd（千级）+ 注册进 epoll** 形成的宽图，
   7 次 `epoll_ctl` 只是收尾结构操作。
   **回收手段已确认**（scoping §2.7）：`fcntl(fd, F_SETPIPE_SZ, bytes)` 缩放管环
   后 `F_GETPIPE_SZ` **回读校验**（`cmp w0, w22` 不符即失败退出）——
   即日志里的 `resize_sample`。缩容走 `pipe_resize_ring()` 释放旧
   `pipe->bufs`，产生 `pipe_buffer` 槽位 UAF 窗口；回读是必要条件而非可选确认。
   **仍未确认**：`fake_count` 的落点、`EPOLL_CTL_DEL` 在其中的确切角色、
   `fake_fllink` 偏移量 `+8` 的选取依据（**毒值形式已确认**，见 scoping §2.8：
   `fake_fllink = base | 0x108 = LIST_POISON1 + 8`）。
4. **仍未确认**：`gen`/`refs`/`depth`/`refcount` 四个偏移在 6.12.58 上的真值。
   `preload.so` 串里的 `0xa8/0xb0/0xb8/0xbc` 是通用值；main 分支源码
   推算与该串**不自洽**（`refs` 若在 `0xb0` 占 16B 至 `0xc0`，与
   `depth=0xb8` 冲突），故不可替代。需 6.12.58 的 BTF 或真机读回（批次 B 前置）。
5. **含义已确认、写入点未定位**：`bit4` = `PIPE_BUF_FLAG_CAN_MERGE`（scoping §2.6.1，
   置位后 `pipe_buf_merge()` 可不拷贝直接串接页，是把受控页挂进管环的前提）。
   在 `pipe_buffer.flags`(0x18) 上的**具体写入指令**仍未定位。

**批次 D 的设计约束已明确**：写入目标是普通 fd + 命令字驱动，
不涉及把内核地址当 fd；建图需先扩 `RLIMIT_NOFILE` 并批量开 fd。

### 批次 D：实现回收 + 受控写入

按 scoping §6 依赖顺序：`late_refs` 诱饵 → 槽位选取与 `RECLAIM_HIT` 两模式 →
`fake_fllink` + `pipe_flags` bit4 改写 → `pipe_worker` 线程模型。

### 批次 E：独立验证

用 `generation`/`refs`/`depth`/`refcount` 哨兵 + 经 carrier 的 readback
替换 `*verify == value` 自读回（`fd_graph_route.cpp:267`）。

### 批次 F：真机门禁

**必须冷启动**；固定 CPU 对；单 route；KernelSU 未加载。

## 4. 所有权与生命周期审查（AGENTS.md 强制，批次 D 适用）

| 对象 | 起点 | 所有者 | 访问者 | 终结点 | 释放者 |
|---|---|---|---|---|---|
| `epoll_fd` / `pipe_read` / `pipe_write` | `prepare()` | `FdGraphRoute`（`UniqueFd`） | consumer 线程 | `destroy()` | `reset()`；stuck 时 `retain_for_process_lifetime()` |
| `consumer_thread` | `prepare()` | `PthreadOwner` | `disarm()` | join 后 | `release()` |
| **`pipe_worker`（新增）** | 批次 D | `PthreadOwner` | 主线程等待其 payload 写 | **必须先于 pipe fd 关闭** | `request_stop()`+`join()` |
| **槽位引用（新增）** | 批次 D | worker 线程 | 主线程**不得**在 free 后访问 | worker 停止访问后 | 内核侧（受控对象） |
| reclaim/drain/expand region | `execute()` | `MappedRegion` | 主线程 | `execute()` 返回 | RAII |

必须遵守的既有顺序（重构不得改变）：

1. 所有参与者**停止访问** → join worker → 再 unlink/释放管道槽。
2. `disarm()` 必须在 `destroy()` 之前（`do_fd_graph_fake_lock_route` 已如此）。
3. `consumer_stuck` 的既有兜底路径（`retain_for_process_lifetime()` +
   `ROUTE_DIRTY_FAILURE`）**保持不变**，新增 worker 也要纳入该判定。

**UAF 边界**：被回收的 `pipe_buffer` 槽位是漏洞原语（**唯一**允许的
use-after-free）；辅助对象、race 状态、缓冲区、同步资源**一律不得**跨回收点访问。

## 5. 验证计划（每批门槛）

批次 A/B/E（普通改动）：

```sh
make -C src native-host-tests
make -C src ghostlock          # NDK 构建零警告
make -C src lint-tidy          # 0 findings
./gradlew :app:testDebugUnitTest
./gradlew exportKernelProfiles
```

批次 D/F（攻击关键路径）—— 门槛全量：

1. `python3 tools/cmp_disasm.py <baseline> build/native/ghostlock`
   对 8 个攻击函数做逐函数核对；字节差异无法证明不影响
   「攻击代码 ↔ 资源准备/回收」顺序时，**停止该批次并调查**。
2. 真机门禁：**冷启动**、固定 CPU 对、单 route、KernelSU 未加载。
3. 日志归档至 `Download/ghostlock-debug-log/<时间>/`，按
   `docs/analysis/device-gates/` 格式记录（失败与成功同等归档）。
4. 核心攻击函数的资源准备/存活期/回收代码须反汇编核对相对顺序不变。

## 6. 风险与停止条件

- **已知**：历史上有「重构漏回收 PI 内存导致 panic」的先例；本计划触及
  同类资源（管道槽），批次 D 必须逐条过 §4 的审查表。
- **归因限制**：`KERNEL-PANIC-01` 允许同构建 PASS/panic/PASS；
  判定因果要求同构建复现 + 冷启动复跑，不得凭单次结果。
- **停止条件**：
  - 批次 C 的三项遗留（scoping §2.5.5：`pipe_buffer` 槽位重占机制、
    `gen`/`refs`/`depth`/`refcount` 真值、bit4 写入点）未取得指令级证据
    → 不进批次 D。**其中第二项需 BTF/真机读回**，当前设备为 production build
    （`adb root` 不可用、`/sys/kernel/btf/vmlinux` 拒绝读取），工作区亦无
    `boot.img`/`vmlinux`/BTF，故**批次 B 在拿到 BTF 前不得填值**。
  - 批次 A 后真机仍 panic 且 `chain_hits` 仍为 0 → 说明破坏源不在无效写入，
    需回到批次 C 重新定位，不得继续叠加机制。
  - `cmp_disasm` 出现无法解释的攻击函数差异 → 停止并调查。
- 批次 A/B 之间若真机不再 panic，仍**不得**标记 6.12.58 为 supported：
  `chain_hits` 未成功即 W1 未完成。

## 7. 评审要点

批次 C（只读分析）已完成大部分，结论见 scoping §2.4/§2.5/§2.6。请确认：

1. **批次顺序**：A（移除无效与错误代码，低风险对照）→ B（几何扩展，依赖 BTF）
   → D（实现投递）→ E（独立验证）→ F（冷启动门禁）。是否认可先做 A？
2. **批次 B 的 4 个新字段**（`gen`/`refs`/`depth`/`refcount`）属 wire/profile
   格式变更，影响面大于 route 本身；且**当前无法验证取值**。是否接受
   「拿到 BTF 后再做」，还是希望本轮先只做 A？
3. **投递机制的设计前提**：batch D 是移植 `preload.so` 已验证的投递路径，
   落点沿用已验证的 waiter 常量（§1.2）。是否同意「先完成批次 C 遗留的
   `pipe_buffer` 槽位重占机制取证，再评审批次 D」？
4. **BTF 来源**：需要 6.12.58 的 `boot.img`（或可读 BTF 的设备）。
   当前 production 设备无法读取，是否可提供 boot.img？