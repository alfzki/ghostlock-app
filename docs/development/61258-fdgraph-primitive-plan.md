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

反汇编 `preload.so` 的 `pipe_worker` / `redirect` / `late_refs` 处理函数，
把 scoping §2.3 的推断升级为指令级事实。**批次 D 的设计依赖此批结果**，
故 C 未完成前不进入 D。

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
  - 批次 C 未能把 §2.3 推断升级为指令级事实 → 不进批次 D。
  - 批次 A 后真机仍 panic 且 `chain_hits` 仍为 0 → 说明破坏源不在无效写入，
    需回到批次 C 重新定位，不得继续叠加机制。
  - `cmp_disasm` 出现无法解释的攻击函数差异 → 停止并调查。
- 批次 A/B 之间若真机不再 panic，仍**不得**标记 6.12.58 为 supported：
  `chain_hits` 未成功即 W1 未完成。

## 7. 评审要点

请确认：① 批次顺序（A 先做对照）是否认可；② 批次 B 的 4 个新字段是否纳入本轮
（属 wire 格式变更，影响面大于 route 本身）；③ 是否同意批次 C 完成后再次评审再进 D。