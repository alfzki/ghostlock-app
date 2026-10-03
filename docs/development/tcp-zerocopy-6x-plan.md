# tcp_zerocopy 路由支持 6.12 计划（2026-10-02）

## 现状与基线

- 分支：`main`，基线 commit `e7cb024`（`merge(vr-ko): bring vr-ko-bypass-dev …`）。
  本次会话的全部改动**尚未提交**（30 个已跟踪文件修改 + 2 个未跟踪新文件）。
- 设备：Vivo V2514（X300 Pro），MediaTek **MT6993**，内核
  `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`，Android 16。
- 已完成并验证的 profile 事实（`app/src/main/assets/kernel_profiles/6.12.58-….conf`）：
  - `kernel_phys_load = 2147418112`（`0x7fff0000`）、`kernel_phys_offset = 2147483648`
    （`0x80000000`），由仓库自带 `tools/mtk-phys/mtk-phys.sh` 在真机实测。
  - `task_struct` / `cred` / `kernelsnitch` 与已验证的 `6.12.23-android16-5` 基线
    **逐字节相同**；`vr_guard` 为 BTF 推导（`funcs_offset=72`）。
  - GLK1 golden：`c59072245c33df5d00e515abda324bac092102e0c06c2f078c6bf82874e7c7cb`。
- **已知问题：`select_stack` 路由在本内核上已被证明不可用**（详见下一节），
  因此 W1 无法完成，`ancillary::AncillaryStage::PreSpawn` 的 vivo vr.ko 中和逻辑
  在真机上从未被执行到（仅有主机侧测试覆盖）。

### select_stack 不可用的证明（已完成，S1 验证）

用 `tools/extract_rs/examples/disasm_func` 对本机 `boot.img` 反汇编，逐字节复核：

1. 偏移量 `shift = 14` 是**真实测量**，非链式推导的假象：
   - pselect 链 `__arm64_sys_pselect6(0xa0) → core_sys_select(0x1b0)`，合计 592
   - futex 链 `__arm64_sys_futex(0x80) → futex_wait_requeue_pi(0x1c0)`，合计 576
   - `pselect_buffer = 0x40`、`waiter_local = 0xa0`
     （注意 `derive.rs:392` 中键 `"futex_wait"` 对应的符号是
     `futex_wait_requeue_pi`，真实锚点为 `add x27, x26, #0x28`）
   - `delta = -416 - (-528) = 112` 字节 → `shift = 14` qword
2. 路由可寻址窗口为 `global_word ∈ [0,14]`
   （`PSELECT_ROUTE_NFDS=320` ⇒ `words_per_set=5`，`set_idx` 仅接受 0..2），
   而非 compact 分支的 waiter 表占 word 2..14，`global_word = shift + word`，
   故只有 `shift ≤ 0` 可行，`shift=14` 时 13 个 word **一个都放不下**。
3. **该窗口无法扩大**。`core_sys_select@0x15ad80` 反汇编显示内核仅在
   `round_down(FDS_BYTES(nfds), 8) < 43` 时把 `fd_set` 放在**内核栈**上：

   ```
   0094 add  x8, x24, #0x3f              ; x24 = nfds
   0098 lsr  x8, x8, #0x3                ; x8  = FDS_BYTES(nfds)
   009c and  x25, x8, #0x1ffffffffffffff8 ; x25 = 向下取整到 8 的倍数
   00a4 cmp  x25, #0x2b                  ; 43
   00a8 b.hs → 0x288 … 02a0 bl 0x1054e8  ; kmalloc_node()（堆）
   ```

   `nfds=320 → 40B → 栈`；`nfds=321 → 48B → 堆`；`nfds=640 → 80B → 堆`。
   堆上的 `fd_set` 永远无法与栈上的 futex waiter 重叠。
   **`PSELECT_ROUTE_NFDS = 320` 已是硬上限**，提高它不是"不够"而是"直接破坏原语"。

**哪一条才是决定性的（复核时勿被误导）：** 第 3 点（nfds 上限）只是**辅助证据**，
单独并不能证明不可行——若 `waiter_shift` 能取 0，非 compact 的 word 2..14
是**放得下**的。真正的**决定性约束**是第 1+2 点的组合：

- `waiter_shift` 在本内核是**被推导出来的**（=14），不是可选参数；
- 因此 waiter 需要落在 `global_word ∈ [14, 27]`；
- 而三个 40 字节的 `fd_set` 只提供 `[0, 14]`。

`[14,27] ∩ [0,14]` 为空 ⇒ 不可行。**两条缺一不可**：只有「推导出的 shift=14」
而没有「窗口无法扩大」，则理论上还有救；只有「窗口上限」而没有「shift=14」，
则本可行。

### tcp_zerocopy 可行性判定（批次 1，**已通过：原语存在 + 偏移正确**）

**原语存在：** 本镜像无 `tcp_zerocopy_receive` 符号，但 `do_tcp_getsockopt` 里有
两处直接调用 `tcp_zerocopy_vm_insert_batch@+0x10fc08c`（`0de0`、`0e90`）。
且该路由**不受** select_stack 的 15-qword 内核栈窗口约束（它写的是攻击者自有的
punched memfd），这是它成为唯一候选的根本原因。

**偏移正确（已从本镜像二进制直接验证）：**

```
0b44 ldr x25, [sp]        ; x25 = 用户传入的 optlen
0b48 ldr x0,  [sp, #0x10]  ; x0  = 内核目标缓冲
0b4c mov x1, x23           ; x1  = 用户源指针
0b54 mov x2, x25           ; x2  = 拷贝长度 = 用户的 optlen（非 sizeof）
0b58 bl 0x1764f4           ; copy_from_user(dst, user_src, optlen)
0b64 mov w8, w25
0b6c sub w2, w8, #0x40     ; optlen - sizeof(zc)  ⇒  sizeof(zc) = 0x40
0b7c bl 0x16ab50           ; check_zeroed_user(dst, 0x40, optlen - 0x40)
```

由此得到两条独立结论：

1. `sizeof(struct tcp_zerocopy_receive) = 0x40`。路由传的 `optlen = 0x40`
   **恰好等于** `sizeof`，因此 `len > sizeof(zc)` 分支不会触发，
   尾部的非零字节不会招致 `-EINVAL`。
2. 拷贝长度取的是**用户的 optlen**，所以 64 字节**全部**被植入，
   `zc[0x28]` 与 `zc[0x30]` 均**真实生效**。

**两处此前的错误判断，均已撤回：**

- ❌「`struct tcp_zerocopy_receive` 是 `0x30` 字节，故 `0x30` 处写入越界失效」
  ——错在引用了 `struct tcp_zerocopy`（`TCP_ZEROCOPY` 的 set/get 结构，0x30 字节），
  而 `getsockopt(TCP_ZEROCOPY_RECEIVE)` 用的是 `struct tcp_zerocopy_receive`（0x40 字节）。
- ❌「`do_tcp_getsockopt` 中找不到 `cmp #0x30`，故无法判定」——不成立：
  `0x30`/`0x3b` 是 `switch (len)` 的**跳转表项**（位于 `.rodata`），不是立即数。

**另一处撤回：** 本节一度据「RX 侧符号全部缺失」推断路由不可用，亦不成立——
`tcp_recv_zc` / `sock_recv_zc` / `tcp_zerocopy_receive` 都是 `net/ipv4/tcp.c` 的
**static 函数**，与 `do_tcp_getsockopt` 同属一个编译单元，内联后根本不会进入
kallsyms；且 `copy_to_user` 作为 `EXPORT_SYMBOL` 符号**同样缺失**，说明本镜像的
符号恢复本身不完整，故「符号缺失」不能作为「代码缺失」的证据。

**结论：批次 1 通过。** 原语存在且偏移对 android16-6 正确，
因此**批次 2（把偏移做成 profile 字段）不需要**，
`report.rs` / `analysis.rs` 的三处 6.1-only 门禁可以解除。

### 已知缺口（本次工作前既已存在，非本计划引入）

`6.12.30-android16-5-g1750f757fabe-ab13938768-4k`（Lenovo Legion Tab Gen 5）
是一个已列入 `SUPPORTED_DEVICES.md` 的真机验证 profile，但它**没有** golden 覆盖：
`git log -S` 显示它从未出现在 `native-doc-golden.sha256` 中，因此
`NativeDocumentEquivalenceTest` 从未冻结过它的 wire 字节。

后果：若将来有人改动该 profile 的字段顺序/编码，测试不会发现。

本计划**不顺带修**它（那是与本计划无关的共享 fixture 变更）。若要补齐，
其当前字节的 sha256 为
`3f01349e5286b5b19bcf83e2a073d49f209d11b87bb97495d52acc7ecfb97045`，
补一行即可纳入覆盖。

## 目标与约束

### 目标

1. 让 `tcp_zerocopy` 路由能在 6.12（含本 MTK 内核）上完成 W1。
2. 从而使 `ancillary::AncillaryStage::PreSpawn` 的 vivo vr.ko 中和逻辑
   首次在真机上可达，并产出硬件证据（日志中出现
   `vr global: disarming sys_exit probe` 与 `vr.ko sys_exit probe neutralized`）。

### 非目标（明确不做）

- 不修改 `select_stack` 的 `PSELECT_ROUTE_NFDS` 或新增窗口宽度 profile 字段
  ——已证明不可行，加了反而破坏原语。
- 不改动 `kernelsnitch/` 上游移植代码。
- 不改动 `LegacyProfileConverter.kt` 的 v1 转换。
- 不在 6.12 上启用 `multicast_waiter`（该路由仅支持 5.x）。
- 本计划**不包含**任何真机 exploit 运行；门禁运行需单独获得用户批准。

### 约束

- 真机门禁前不得运行 exploit（此前已因 select_stack 失败导致 3 次 kernel panic）。
- 13 个已验证的 `6.12.*-android16-5` builtin profile 的行为**一个都不能变**。
  其中 12 个有 golden 覆盖，这 12 条哈希必须逐一保持不变。
  （第 13 个 `6.12.30-android16-5-g1750f757fabe-ab13938768-4k`（Lenovo Legion Tab Gen 5）
  **没有** golden 覆盖——这是本次工作之前就存在的覆盖缺口，见「已知缺口」。）
- 不新增 profile/wire 传输格式版本号（本分支统一 v2，按键是否出现表达 presence）。

## 改动清单

### 批次 1：提取器 —— 解除三处 6.1-only 门禁（只读判定**已通过**）

批次 1 的只读判定已完成并**通过**：原语存在，且 `zc[0x28]`/`0x30` 对 android16-6
**正确**（`sizeof(struct tcp_zerocopy_receive) = 0x40`，拷贝长度取用户 optlen，
故 64 字节全部植入）。因此**无需**新增偏移推导，**批次 2 取消**。
本批次只剩解除门禁：

| 文件 | 改动 | 理由 |
| --- | --- | --- |
| `tools/extract_rs/src/report.rs:67-68` | `build_report` 的 `compact_waiter=1` + `mm_struct_sz=0x400` 仍限 6.1；6.12 不应伪造 `mm_struct_sz=0x400` | 该 SLUB stride 是 6.1 设备实测值，不可外推 |
| `tools/extract_rs/src/report.rs:223-226` | `conf_route_geometry` 的 tcp 分支：6.12 输出 `compact_waiter = 0`（或省略），不再留 `null` | 路由不读该字段，但 profile 不应声称未验证的 compact 家族 |
| `tools/extract_rs/src/analysis.rs:287-289` | `suggest_route`：6.12 在 tcp 原语可用时允许推荐 `tcp_zerocopy` | 现仅对 `6.1` 推荐，导致 6.12 永远被导向不可行的 `select_stack` |
| `tools/extract_rs/src/*`（测试） | 新增单测锁定「6.12 + tcp 原语存在 ⇒ 推荐 tcp_zerocopy」与「compact_waiter 不为 1」 | 防止门禁被无意放宽或误改 |

### 批次 2：**已取消**（原判定「落点不同」不成立）

原计划在此把 `zc` 偏移做成 profile 字段（`zc_task_off`/`zc_lock_off`）。
既然批次 1 证实偏移本就正确，**本批次不需要**，`src/core/**` 无需改动。

### 批次 3：Kotlin 线格式 + 新 profile

| 文件 | 改动 | 理由 |
| --- | --- | --- |
| `profile-core/.../NativeProfile.kt` | `RouteGeometry` 增加同名字段 + `from()`/`entries()`/`apply()` | 双侧一致性由 `route_catalog_test` / wire 测试保证 |
| `profile-core/.../profile/ProfileResolver.kt` | `KnownTopLevel` 登记新键 | 同上 |
| `docs/kernel_profiles/PROFILE_SCHEMA.md` | 补字段说明 | 字段变更必须回写文档 |
| `app/src/main/assets/kernel_profiles/6.12.58-….conf` | ~~切到 `tcp_zerocopy`，写入推导出的 `compact_waiter=0`~~ **已回滚，见「批次 3 阻塞」** | 该 profile 的路由字段当前是 select_stack |
| `app/src/test/resources/native-doc-golden.sha256` | 随 profile 回滚同步（仅此一条） | 其余 51 条必须不变 |

### 批次 3 阻塞：路由的 zc 偏移是 compact 家族常量

批次 1 只证明了**原语存在**且 `zc[0x28]`/`zc[0x30]` 能真实植入用户缓冲区。
它**没有**证明这两个偏移对得上本内核的 forged waiter 几何。实测二者并不对：

- `tcp_zerocopy_route.cpp:318-319` 把 `waiter_task`/`fake_lock` 写到
  `zc[0x28]`/`zc[0x30]`，即假定 `rt_mutex_waiter` 的 `task`/`lock`
  落在 `0x28`/`0x30` —— 这是 **6.1 compact 家族**的布局。
- 本内核 waiter 为 **non-compact**（`tree@0x0` 与 `pi_tree@0x28` 并存，
  BTF 实测），`task`/`lock` 不在 `0x28`/`0x30`。
- 路由**不读**任何 waiter 几何字段，故 profile 无从覆盖该假设。

因此 `compact_waiter=0` 不是「可以照填的推导值」，而是**声明本设备
不属于该路由唯一支持的家族**。把它写成 `1` 可以让 app 校验与
`ProfileMigrationEquivalenceTest` 同时变绿，但代价是让路由按 compact
偏移向 non-compact waiter 写入 `task`/`lock` —— 写坏内核对象，
正是三次 panic 的成因类别。

本节撰写时该 profile 为 `select_stack { waiter_shift = 0 }`，据此判定 6.12.58
的 W1「当前不支持」。**该配置已于 `aed09ad` 改为 `route.fd_graph`**（新增的
第四条 middleware），因此 profile 现在不再有 `select_stack` 块，也无
`compact_waiter`。**「select_stack 在 6.12.58 不可行」这一结论不受影响**
（依据见上节与 `:379-385` 的外部佐证），只是「profile 保持 select_stack」
的表述已过时。6.12.58 当前路线见
`docs/development/61258-fdgraph-primitive-plan.md`。

结论：`compact_waiter` 对 tcp 路由而言是**家族标记**而非运行期开关；
Kotlin 侧 `compact_waiter` 必填非零的校验（`AndroidProfileConfigController.kt:145`）
是**有效护栏**，不得为了让测试变绿而放宽。

### 批次 3' 决策门（2026-10-02）：机制未确认，**不实施**

用户已批准方向「参数化 waiter 几何」，并要求**路线跑通前不碰真机**。
本节记录实施前必须先关掉的缺口。**本节不是实施计划。**

#### 现状与基线

- 基线 commit：`e7cb024`（其余工作树改动未提交）
- 6.12.58 profile = `select_stack { waiter_shift = 0 }`，已知不可用；
  本地门禁全绿：app 80 + profile-core 18 = 98 项、cargo 43 项、
  NDK 零告警、`lint-tidy` 0 findings、host 26/26。

#### 已确认事实（可追溯、数字可核对）

1. **6.6/6.12 waiter 几何双源一致**：
   `src/core/kernel/target.h:77-85` 给出
   `FAKE_WAITER_TASK_OFF=0x50`、`LOCK_OFF=0x58`、`PI_TREE_ENTRY_OFF=0x28`、
   `WAKE_STATE_OFF=0x60`、`WW_CTX_OFF=0x68`（合计 0x70）；
   `ghostlock-extract boot.img --analysis` 对本镜像独立输出
   `task=0x50 lock=0x58 pi_tree=0x28 wake_state=0x60 ww_ctx=0x68 size=0x70`。
   ⇒ 常量正确，缺的只是路由不用它们。
2. **compact 对照**：由 `util.cpp` compact 分支反推
   `task@0x30`/`lock@0x38`（历史文档
   `extractor-no-btf-struct-derivation-plan.md:78` 亦记 `waiter->task`(0x30)）。
   ⇒ non-compact 的 task 相对 compact **位移 +0x20**。
3. **0x40 的 zc 窗口不是瓶颈**：按 compact 反推，zc 写入基准比 waiter 基准早
   8 字节（`zc[0x28]`→`waiter+0x30`=task、`zc[0x30]`→`waiter+0x38`=lock）。
   欲命中 non-compact 的 `0x50`/`0x58`，基准须移到 `waiter+0x28`
   （`zc[0x30]`→`0x50`、`zc[0x38]`→`0x58`，末字节 0x3F，仍在 0x40 内）。
   而基准来自路由自己写入的 `zc[0x18]`，属**纯用户态可调量**。

#### 未确认的一环（阻塞实施）

`getsockopt(TCP_ZEROCOPY_RECEIVE)` 究竟把什么写到 `zc[0x18]` 指向的地址：

- 反汇编 `do_tcp_getsockopt@+0x10fa57c`（经 `examples/disasm_func.rs`）：
  两处 `bl tcp_zerocopy_vm_insert_batch`（`0de0`/`0e90`）只传**内核栈**缓冲
  （`sp+0x120`、`sp+0x70`、`sp+0x80`、`sp+0x6c`、`sp+0x20`）与 `x7=[sp]`（optlen），
  未见用户态写入目标。
- `vm_insert_batch@+0x10fc08c` 内部为 `copy_from_user`(`0x1764f4`) /
  `copy_to_user`(`0x125a010`) 对 replay frame 逐帧搬运。
- `execute()` 里 `sendbuf.fill(0x33)`（`tcp_zerocopy_route.cpp:284`）是占位值，
  倾向 (b) 收到的是**已收 TCP 载荷**而非 zc 结构。
- **但伪造 waiter 由 `prepare_skb_payload` 写入 `heap.current.base`**
  （`util.cpp:622`），与 zc 的写入目标 `mapping + page_size` **不是同一块内存**。

⇒ 二者如何衔接（谁把哪块内存变成 PI walk 实际走到的 waiter）**在本仓库与
git 历史中均无记载**；无任何 tcp 路由的真机门禁记录，`docs/analysis/routes.md`
为空。Oracle 独立复核后同样判定「证据不足，无法判定」。

**因此：只加偏移字段并不能让 W1 跑通**，反而会产出一个「校验通过、测试全绿、
实际仍不工作」的配置——与 `compact_waiter = 1` 同类，只是离真相更远。
在此前提下不写实施计划、不改 `src/core/route/`。

#### 定案所需证据（任一即可）

1. `tcp_zerocopy_vm_insert_batch` 的**写入目标地址计算链**（`pgoff`/`cop`
   如何得出），以及被写数据是 zc 结构还是收到的 TCP 载荷；
2. stale waiter 在页内的基准地址，及其与 zc 窗口的对齐关系；
3. 上游参考实现对该机制端到端的描述（本仓库 `README.md` Credits 列出
   `x-spy/CVE-2026-43499-popsicle` 与 `CyberMeowfia`）；
4. 一份**可用的 6.1 镜像**，与本 6.12.58 镜像对比定位那段地址算术。

#### 证据到位后的改动清单（届时才生效）

| 文件 | 改动 | 理由 |
| --- | --- | --- |
| `src/core/profile/model.h` | tcp 路由扩展节增 `waiter_task_off`/`waiter_lock_off` | 双侧一致性由 agreement 测试保证 |
| `src/core/profile/binary.cpp` | 对应 `Field` 表增 `OPT(...)`（与 `kRouteSelect` 同形） | 键名须与 Kotlin 逐字一致 |
| `src/core/route/tcp_zerocopy_route.cpp` | 消费 profile 偏移替换硬编码 `0x28`/`0x30` | 攻击关键路径，需 `cmp_disasm` |
| `profile-core/.../NativeProfile.kt` | 数据类 + `entries()`/`apply()`/`from()` + raw 解析 | v2 线格式，**不新增版本号** |
| `profile-core/.../ProfileResolver.kt` | `nativeValue()` 的 `branchField` 分支登记新字段 | 否则 `route.<name>.*` 查不到 |
| `docs/kernel_profiles/PROFILE_SCHEMA.md` | 补字段说明 | 字段变更必须回写文档 |

会因单侧改动而失败的测试：`profile_binary_test.cpp`、
`NativeProfileDocumentTest.kt`、`ProfileResolverTest.kt`、
`ProfileRoundTripTest.kt`、`HoconSupportTest.kt`、
`NativeDocumentEquivalenceTest`（golden）。

#### 本批次的保留项（不动）

- `LegacyProfileConverter.kt` 的 v1 转换：按 `AGENTS.md`，新 route/新字段不改 v1。
- 线格式**保持 v2**，不得再叠版本号。
- `AndroidProfileConfigController.kt:145-152` 的 `compact_waiter` 非零校验：**不得放宽**。
- 本批次不新增真机门禁（路线未通，门禁无意义）。

## 数据流/控制流差异

- 现状：`pselect6` → 内核栈 `fd_set`（≤40B）→ 与栈上 `futex_wait_requeue_pi`
  waiter 重叠。本内核 waiter 偏移 +112B，超出 15 qword 窗口 → 不可行。
- 目标：`getsockopt(TCP_ZEROCOPY_RECEIVE)` → 攻击者完全控制的
  **punched memfd 页**（`TCP_PUNCH_SHMEM_LEN = 16MB`，`fallocate` 打洞），
  zc 输出结构与伪造 waiter 在该页内重叠。
  **该机制不受内核栈 15-qword 窗口约束**，这是它成为唯一候选的根本原因。
- 不变量：
  - 13 个 android16-5 profile 的 `words_per_set` 与全部写入偏移不变
    （`global_word N` 恒定落在字节 `N*8`，已用连续性论证复核）；
  - `ExploitSession` 布局不变（`sizeof == 1648`），新增字段一律走
    `component_ids` 同类 side output；
  - 6.1 的 zc 偏移仍为 `0x28`/`0x30`。

## 兼容性与回滚

- 回滚：批次互相独立，可逐批 `git revert`；wire 新字段为 optional，
  旧 profile 缺键即走回落值，向后兼容。
- 风险（**已发生，且被误判**）：若 6.12 的 zc 输出结构与 6.1 同形
  （`0x28`/`0x30` 恰好一致），批次 1 的推导会得出"无需改动"，此时只做
  profile 路由切换。
  → 实际正是如此：`sizeof(struct tcp_zerocopy_receive) = 0x40`、
  `zc[0x28]=task`/`zc[0x30]=lock` 与 6.1 同形，批次 1 因此判定"无需改
  `src/core/**`"。**该结论混淆了两个几何**：`zc` 输出结构的形状只说明
  这两个词能被真实植入用户缓冲区，**不说明**它们在被覆盖的 forged
  waiter 里恰好落在 `task`/`lock` 上。实测本内核 waiter 为 non-compact，
  二者不对齐。批次 3 已回滚（见上）。
- 风险：若推导无法给出唯一定位（与 pselect 当初同样的"候选不唯一"问题），
  则本计划判定为不可行，应回到"该设备不支持 GhostLock"的结论。

## 验证矩阵

| 批次 | 命令 | 预期 |
| --- | --- | --- |
| 1 | `cd tools/extract_rs && cargo test --release` | 现有 39 项全绿 + 新增用例通过 |
| 1 | `build/extract/release/ghostlock-extract /tmp/ghostlock-payload-117017/boot.img --format conf --route tcp_zerocopy` | 输出 `tcp_zerocopy { compact_waiter = 0, … }`，无 "unverified candidate" 警告 |
| 2 | `make -C src native-host-tests` | 26/26（`tcp_zerocopy_route_test` 除外，见下） |
| 2 | `make -C src ghostlock` | 退出 0，零告警 |
| 2 | `make -C src lint-tidy` | 0 findings |
| 2 | `python3 tools/cmp_disasm.py <baseline> build/native/ghostlock` | 8 个攻击函数 IDENTICAL；`zc` 偏移改动只应影响 tcp 路由 |
| 3 | `./gradlew :app:cleanTest :app:testDebugUnitTest :profile-core:cleanTest :profile-core:test` | BUILD SUCCESSFUL；**golden 仅 6.12.58 一条变化** |
| 3 | `sha256sum` 比对 golden 文件其余 51 行 | 与改动前完全一致 |
| 4（需单独批准） | 真机冷启动门禁，单 route，KernelSU 未加载 | 日志出现 `vr global: …` + `vr.ko sys_exit probe neutralized`，且 `ro.boot.bootreason != kernel_panic` |

注：`tcp_zerocopy_route_test` 在 x86 主机上因内联 arm64 `yield` 无法汇编而
无法编译（既有问题，见 `tcp_zerocopy_route.cpp:47`），非本次引入。

## 明确保留

- `src/core/route/select_stack_route.cpp`：不改动。6.12 上不可用是**内核栈窗口的
  硬限制**，不是代码缺陷；13 个 android16-5 profile 仍依赖它正常工作。
- `AndroidProfileConfigController.kt:145-152` 的 `compact_waiter` 必填非零校验：
  **保留，不得放宽**。它看起来像过时的护栏，实则是当前唯一阻止
  「non-compact 内核 + compact 硬编码偏移」组合的闸门。放宽后
  `compact_waiter=0` 可过校验，路由会按 `0x28`/`0x30` 向 non-compact
  waiter 写 `task`/`lock` → 写坏内核对象。
- `report.rs` 中 `select_stack` 的 `shift > 3` 判定：保留。该阈值对现有布局偏松
  （真实上限是 0），但修正它会改变既有 profile 的产出文案，属独立议题。
- vr.ko 中和逻辑（`vr_guard.*`）：本批次不动。它已经正确接线并有主机测试；
  缺的只是真机可达性。

## 进度

- [x] 证明 `select_stack` 在本内核不可用，且窗口无法扩大（S1，含反汇编证据）
- [x] 证明 tcp_zerocopy 的原语在本内核**真实存在**
      （`do_tcp_getsockopt` 内两处直接 `bl tcp_zerocopy_vm_insert_batch`：
      `0de0` / `0e90`）
- [x] 由 BTF 判定本内核 waiter 为 **non-compact**（`tree@0x0` 与 `pi_tree@0x28`
      并存的双 rb_node 布局）⇒ `compact_waiter = 0`
- [x] 更正一处早期误解（已核实）：`tcp_zerocopy` 路由**根本不读** `compact_waiter`
      —— `grep compact_waiter src/core/route/tcp_zerocopy_route.cpp` 无任何命中。
      对比 `select_stack_route.cpp:169/298/306` 确实分支。**修改前请注意**：
      该字段对 tcp 路由而言是「已验证家族」的**证明标记**，不是运行期布局开关；
      路由永远按固定偏移 `zc[0x28]=task` / `zc[0x30]=lock` 写入
      （`tcp_zerocopy_route.cpp:318-319`）。它的唯一作用是阻止提取器把
      未验证的 layout 声明为 compact-waiter 家族。
- [x] 统计出**三处**独立的 6.1-only 门禁（`report.rs:67-68`、`:223-226`、`:383`），
      外加 `analysis.rs:287-289` 的 `suggest_route` 仅对 6.1 推荐 tcp
- [x] 批次 1：**通过**。原语存在（`0de0`/`0e90` 两处直接
      `bl tcp_zerocopy_vm_insert_batch`）；偏移正确——本镜像
      `sizeof(struct tcp_zerocopy_receive) = 0x40`（`0b6c sub w2,w8,#0x40`
      与 `0b7c bl` 双重印证），且拷贝长度取**用户 optlen**，路由传 `0x40`
      恰好等于 `sizeof`，故 `zc[0x28]`/`0x30` 均真实植入。
- [x] 撤回三处此前的错误判断：①「0x30 越界失效」（误引 `struct tcp_zerocopy`，
      实为 `struct tcp_zerocopy_receive`）；②「RX 侧符号缺失 ⇒ 路由不可用」
      （static 函数被内联，且 `copy_to_user` 亦缺失，证明符号恢复不完整）；
      ③「找不到 `cmp #0x30` ⇒ 无法判定」（`0x30`/`0x3b` 是 `switch(len)` 跳转表项）。
- [x] 修正 `select_stack` 证明的表述：决定性约束是
      **推导出的 `shift=14` 使需求窗口为 `[14,27]`**，而 fd_set 只提供 `[0,14]`；
      nfds=320 上限是**辅助证据**（若 shift 可取 0，word 2..14 本可放下）。两条缺一不可。
- [x] **外部佐证（2026-10-02，公开 PoC 独立复现同一结论）**：CVE-2026-43499 的
      公开 PoC（Sploitus，XiaoBaiLovesStirring，2026-08-24）在同类
      `6.12.58-android16-6` 机型上给出：`waiter word=14, no safe shift exists`，
      并给出可行性判据 `waiter_word + 11 ≤ 14` ⇒ **最大可行 word = 3**。
      与本仓库从 `boot.img` 反汇编独立得出的 `shift=14` / 窗口 `[0,14]` /
      提取器自述「max feasible shift is 3」三方一致。
      ⇒ `select_stack` 在本内核不可用这一结论**不再只依赖本仓库的反汇编**。
      注：该 PoC 称 Android GKI 6.12.x 仍受影响，修复落在 mainline 7.1。
- [x] 批次 1b（部分）：`analysis.rs` 已引入 `PselectVerdict::{Derived,Infeasible,Unknown}`，
      `suggest_route` 仅在 `Infeasible` 时对 6.x 推荐 tcp，`Unknown` 不推荐；
      `main.rs` 调用点同步；新增 4 项单测，`cargo test --release` 43/43 绿。
      **`report.rs:67-68`/`:223-226`/`:383` 三处门禁刻意不解除** —— 它们是
      compact 家族护栏，解除后提取器会产出 app 拒绝（`compact_waiter=0` 校验失败）
      或需谎报 `1` 才通过的 profile。
- [x] 批次 2：**已取消**（偏移本就正确，无需做成 profile 字段，`src/core/**` 无需改动）
- [x] 批次 3：**已回滚**。Kotlin 线格式改动保留（wire 侧 `compact_waiter` 本就存在），
      但 6.12.58 profile 的路由切换已撤销并回到 `select_stack { waiter_shift = 0 }`，
      golden 该条同步为 `c5907224…`。原因见「批次 3 阻塞」。
      证据：app 80 项 + profile-core 18 项 = 98 项全绿，
      `BuiltinProfilesTest` 3/3、`ProfileMigrationEquivalenceTest` 1/1、
      `NativeDocumentEquivalenceTest` 1/1。
- [ ] 批次 3'：**已决策门阻塞（2026-10-02）**。用户已批准方向「参数化 waiter
      几何」并要求路线跑通前不碰真机；但实施前的前提未满足——伪造 waiter
      落在 `heap.current.base`，而 zc 写入目标是 `mapping + page_size`，
      二者衔接方式在本仓库与 git 历史中均无记载，Oracle 复核亦判定
      「证据不足」。详见上方「批次 3' 决策门」。所需证据与到位后的改动清单
      已列全；**证据到位前不写代码、不加偏移字段**。
      **不得**以「谎报 `compact_waiter=1`」或「加字段让测试变绿」换取进展。
- [ ] 批次 4：真机门禁（需用户单独批准；W1 未跑通前无意义）