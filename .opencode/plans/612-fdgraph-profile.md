# L-Level Plan: Create Working 6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k Profile for Vivo X300 Pro Using fd_graph Route

## 1. 현황과 베이스라인 (Current State & Baseline)

### 1.1 Existing Profile
- **File**: `app/src/main/assets/kernel_profiles/6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k.conf` (201 lines)
- **Current route**: `select_stack` with `waiter_shift = 0`
- **Status**: **KNOWN INFEASIBLE** — profile documents architectural ceiling: select_stack cannot bridge the 14-qword gap under 15-qword ceiling (ROOT CAUSE section)
- **Indexed**: Yes, listed in `index.conf` line 66
- **Physical addresses** (from mtk-phys.sh on 2026-10-02):
  - `kernel_phys_load = 2147418112 (0x7fff0000)`
  - `kernel_phys_offset = 2147483648 (0x80000000)`

### 1.2 fd_graph Route Implementation (Already Ported)
- **RouteKind**: `FD_GRAPH = 4` (wire value)
- **Kotlin config**: `profile-core/src/main/kotlin/com/ghostlock/app/data/route/FdGraphConfig.kt` — 12 optional geometry fields
- **Native layout**: `src/core/profile/model.h:207-220` — `FdGraphLayout` struct with 12 `optional<uint32_t>`
- **Route implementation**: `src/core/route/fd_graph_route.{h,cpp}` — `FdGraphRoute` class + `do_fd_graph_fake_lock_route` entry point
- **Catalog availability**: `src/core/route/component_catalog.hpp:47` — `middleware_available(FdGraph)` returns true
- **Pipeline support**: `combination_supported` allows `(RootChild, Cve2026_43499, FdGraph)`

### 1.3 Extractor Gap
- `tools/extract_rs/src/report.rs:207-243` `conf_route_geometry()` handles `select_stack`, `tcp_zerocopy`, `multicast_waiter` only
- **No fd_graph branch** — extractor will emit empty geometry for fd_graph route
- Must manually populate all 12 fd_graph geometry constants

### 1.4 Reference Constants (from preload.so .rodata)
| Constant | Value | Source |
|----------|-------|--------|
| eventpoll_size | 0xd0 (208) | preload.so |
| epitem_ep | 0x48 (72) | preload.so |
| epitem_fllink | 0x50 (80) | preload.so |
| pipe_buffer | 0x28 (40) | preload.so |
| pipe_flags | 0x18 (24) | preload.so |
| pipe_slots | 32 | preload.so |
| pipe_ring | 0x500 (1280) | preload.so |
| pipe_object | 0x800 (2048) | preload.so |
| graph_width | 96 | preload.so (GRAPH_READY) |
| graph_fanout | 256 | preload.so (GRAPH_READY) |
| graph_edges | 24576 | preload.so (GRAPH_READY) |
| objects_per_order3 | 16 | preload.so |

### 1.5 Resources Available
- **Firmware payload.bin**: 12.5GB at `/home/alfzki/Documents/Vivo x300 pro thinkering/firmware-x300-pro/20260904221626521a6e0027a63d640cbc7c8af63e9ff3/payload.bin`
- **Extracted partitions**: `partition-dump/vivo_x300_pro_dump_20261002_221330/partitions/` — `boot_a.img`, `boot_b.img` (100MB each)
- **preload.so**: `/home/alfzki/Documents/Vivo x300 pro thinkering/X300_Temporary_Root_Tutorial_and_Tools/preload.so` (verified working fd_graph primitive)
- **mtk-phys.sh**: `/home/alfzki/Documents/Vivo x300 pro thinkering/ghostlock-app/tools/mtk-phys/mtk-phys.sh` (for on-device physical address derivation)

---

## 2. 목표와 제약 (Goals & Constraints)

### 2.1 Primary Goal
Create a **verified, runnable** kernel profile for `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` using the **fd_graph** middleware route that:
- Passes app pre-execution validation (zero invalid paths)
- Completes W1 (SELinux), W2 (cred/uid 0), W3 (seccomp) on device
- Hands off to `root_child` → `ksud` for KernelSU module loading
- Produces device-gate logs in `Download/ghostlock-debug-log/<timestamp>/`

### 2.2 Non-Goals
- Do NOT modify `select_stack` route or its geometry — it is architecturally infeasible on this kernel
- Do NOT modify `tcp_zerocopy` route — geometry mismatch (non-compact waiter vs compact constants)
- Do NOT add new extraction derivation for fd_graph in extractor (L-level change requiring plan)
- Do NOT modify `kernelsnitch-6x.conf` or `credential-6x.conf` — shared 6.x constants are correct
- Do NOT touch `LegacyProfileConverter.kt` (v1 JSON conversion) — irrelevant for v2 profile

### 2.3 Constraints
- **Exact `uname -r` match required**: profile release string must be `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **MediaTek physical addresses mandatory**: `kernel_phys_load` + `kernel_phys_offset` must be set (runtime falls back to wrong SoC formula otherwise)
- **Profile must be in index.conf** to be selectable at runtime
- **Carrier-DSO hijack dropped**: GhostLock uses W1/W2/W3 → root_child → ksud (preload.so uses carrier-DSO; not applicable)
- **Validation gates**: cold boot, fixed CPU pair, KernelSU unloaded, single route

---

## 3. 작업 청사진 (File-by-File Changes)

### 3.1 New/Modified Files

| File | Action | Description |
|------|--------|-------------|
| `app/src/main/assets/kernel_profiles/6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k.conf` | **OVERWRITE** | Replace select_stack profile with fd_graph profile containing all 12 geometry constants + verified physical addresses |
| `app/src/main/assets/kernel_profiles/index.conf` | **MODIFY** | Ensure entry exists (already present line 66); no change needed unless disabling old profile |
| `tools/extract_rs/src/report.rs` | **NO CHANGE** | fd_graph geometry derivation NOT added (out of scope for this plan) |
| `tools/extract_rs/src/main.rs` | **MODIFY** | Add `fd_graph` to CLI `--route` choices (line 58) |

### 3.2 CLI Route Value Fix (Required for Extractor --route fd_graph)
**File**: `tools/extract_rs/src/main.rs:58`
```rust
// Current:
#[arg(long, value_parser = ["tcp_zerocopy", "select_stack", "multicast_waiter"])]
route: Option<String>,

// Change to:
#[arg(long, value_parser = ["tcp_zerocopy", "select_stack", "multicast_waiter", "fd_graph"])]
route: Option<String>,
```
**Rationale**: Extractor `--route fd_graph` must be accepted for future extraction runs. This is a trivial S-level change.

---

## 4. 데이터/제어 흐름 차이 (Data/Control Flow Diffs)

### 4.1 Profile Resolution Flow (Unchanged)
```
index.conf → ProfileMerger.resolveMerged() → ProfileResolver.validateMerged() → NativeProfileDocument → GLK1 binary → native ProcessBuilder
```
No changes to merger, resolver, or binary format.

### 4.2 Route Selection at Runtime (Unchanged)
```
TargetProfile.route() → RouteKind::FdGraph (wire=4) → component_catalog::dispatch_target() → FdGraphPolicy::run() → do_fd_graph_fake_lock_route()
```
Profile's `route { fd_graph { ... } }` section drives middleware selection.

### 4.3 Geometry Consumption (fd_graph Specific)
```
FdGraphRoute::prepare() → profile.fd_graph_layout() → FdGraphLayout { eventpoll_size, epitem_ep, ... }
```
All 12 fields are `optional<uint32_t>`; route logs each at prepare time (fd_graph_route.cpp:150-158). Missing fields = 0 in log but route proceeds.

### 4.4 Attack Flow Difference (select_stack → fd_graph)
| Stage | select_stack (old) | fd_graph (new) |
|-------|-------------------|----------------|
| Primitive | CVE-2026-43499 (futex requeue_pi) | CVE-2026-43499 (same backend) |
| Middleware | select() stack waiter race | epoll/fd graph UAF via pipe/socketbuffer |
| Key objects | rt_mutex_waiter on stack | eventpoll, epitem, pipe_buffer, graph edges |
| Geometry | waiter_shift (single int) | 12 constants (struct sizes, offsets, graph params) |
| Consumer thread | pselect loop | epoll consumer thread (fd_graph_route.cpp:143) |

---

## 5. 호환성/롤백 (Compatibility & Rollback)

### 5.1 Backward Compatibility
- **Profile format**: v2 (GLK1) unchanged — fd_graph section is additive
- **Native binary**: `ghostlock` ELF unchanged — fd_graph route compiled in
- **Kotlin config**: `FdGraphConfig` already exists, no schema change
- **Index entry**: Already present, no migration needed

### 5.2 Rollback Strategy
If fd_graph profile fails device validation:
1. Revert `6.12.58-...-4k.conf` to select_stack version (git restore)
2. Remove fd_graph entry from index.conf (or keep — select_stack profile has zero invalid paths but panics)
3. Document failure in device-gate log per `docs/development/documentation-standards.md`

### 5.3 No Breaking Changes
- No wire format changes (v2 stable)
- No component catalog changes (fd_graph already registered)
- No execution settings changes (reuse existing tuning)

---

## 6. 검증 매트릭스 (Verification Matrix)

### 6.1 Build Verification (Must Pass Before Device)

| Command | Expected Result |
|---------|-----------------|
| `make -C src ghostlock` | NDK build succeeds, `build/native/ghostlock` exists |
| `make -C src native-host-tests` | All host unit tests pass (including fd_graph_route_test.cpp) |
| `make -C src lint-tidy` | clang-tidy: 0 findings |
| `./gradlew :app:assembleDebug` | APK builds successfully |
| `./gradlew :app:testDebugUnitTest` | Unit tests pass (including BuiltinProfilesTest) |
| `./gradlew exportKernelProfiles` | Generates `build/kernel-profiles/6.12.58-...-4k.bin` (GLK1) |

### 6.2 Extractor Verification (Source of Offsets)

| Command | Expected Result |
|---------|-----------------|
| `cd tools/extract_rs && cargo build --release` | `build/extract/release/ghostlock-extract` built |
| `ghostlock-extract boot_a.img --format conf --route fd_graph --out /tmp/test.conf` | Emits profile with route=fd_graph, all task_struct/cred/offset fields populated, **fd_graph geometry empty** (known gap) |
| `ghostlock-extract boot_a.img --analysis` | Analysis report shows kernel family, waiter layout, primitive status |

### 6.3 Device Gate Verification (Mandatory)

| Step | Command / Action | Success Criteria |
|------|------------------|------------------|
| 1. Push binary | `adb push build/native/ghostlock /data/local/tmp/ghostlock` | File exists, executable |
| 2. Push profile | `adb push build/kernel-profiles/6.12.58-...-4k.bin /data/local/tmp/profile.bin` | File exists |
| 3. Cold boot device | Power off → power on | Clean boot, no KernelSU loaded |
| 4. Fix CPU pair | `echo 0-1 > /sys/devices/system/cpu/cpufreq/policy0/related_cpus` (or profile's selected_cpus) | Consumer on CPU 1, main on CPU 0 |
| 5. Run exploit | `adb shell /data/local/tmp/ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin` | **W1: SELinux=0**, **W2: uid=0**, **W3: seccomp bypassed**, handoff to root_child |
| 6. Verify logs | `adb pull /sdcard/Download/ghostlock-debug-log/<timestamp>/` | Log shows `route = fd_graph`, all 12 geometry constants logged, W1/W2/W3 PASS, handoff success |
| 7. KernelSU module | Check `lsmod | grep kernelsu` or `su -c id` | Module loaded, root shell works |

### 6.4 cmp_disasm Verification (Attack Path Change)
Since this is an **attack critical path change** (route switch), per AGENTS.md:
```bash
python3 tools/cmp_disasm.py <baseline-binary> build/native/ghostlock
```
**Required**: 8 attack functions IDENTICAL (strict) or annotated differences reviewed.
- Baseline: previous working build (if any) or known-good commit
- Functions: backend (cve_2026_43499), middleware (fd_graph), session/heap setup

---

## 7. 명시적 보존 (Explicitly Preserved)

| Item | Status | Reason |
|------|--------|--------|
| `credential-6x.conf` include | **PRESERVED** | Shared 6.x cred template correct |
| `kernelsnitch-6x.conf` include | **PRESERVED** | Shared 6.x KernelSnitch tuning correct |
| `task_struct` offsets | **PRESERVED** | From existing verified profile (device-accurate) |
| `cred` template | **PRESERVED** | From existing profile / extractor derivation |
| `offset` block (init_task, init_cred, selinux_enforcing, etc.) | **PRESERVED** | Device-accurate, verified by extractor |
| `vr_guard` block | **PRESERVED** | BTF-derived funcs_offset=72, tag_b_off=44 |
| `kernel_phys_load` / `kernel_phys_offset` | **PRESERVED** | Measured on device 2026-10-02 |
| `execution` tuning | **PRESERVED** | Include `execution-tuning.conf` + fd_graph-specific if needed |
| `fallback { to = "none" }` | **PRESERVED** | No fallback route for fd_graph |

---

## 8. 진행도 체크리스트 (Progress Checklist)

### Phase 0: Preparation
- [ ] Read preload.so .rodata strings to confirm 12 fd_graph constants
- [ ] Verify boot_a.img is valid Android boot image (ANDROID! magic)
- [ ] Build extractor: `cd tools/extract_rs && cargo build --release`

### Phase 1: Offset Extraction
- [ ] Run extractor on boot_a.img: `ghostlock-extract boot_a.img --format json --out /tmp/offsets.json`
- [ ] Run extractor analysis: `ghostlock-extract boot_a.img --analysis --out /tmp/analysis.txt`
- [ ] Verify all required symbols present (task_struct, cred, offset fields)
- [ ] Note any missing fields for manual completion

### Phase 2: Profile Construction
- [ ] Create new fd_graph profile content (see §8.1 template below)
- [ ] Overwrite `6.12.58-...-4k.conf` with fd_graph profile
- [ ] Verify HOCON syntax: `./gradlew exportKernelProfiles` (should generate .bin)
- [ ] Run `BuiltinProfilesTest` to confirm zero invalid paths

### Phase 3: Native Build
- [ ] `make -C src ghostlock` — NDK build
- [ ] `make -C src native-host-tests` — host tests
- [ ] `make -C src lint-tidy` — clang-tidy clean

### Phase 4: Device Validation
- [ ] Push binary + profile to device
- [ ] Run mtk-phys.sh on device (if physical addresses need re-verification)
- [ ] Cold boot, fixed CPU pair, KernelSU unloaded
- [ ] Execute ghostlock with profile
- [ ] Capture device-gate logs
- [ ] Verify W1/W2/W3 + handoff

### Phase 5: Evidence Archival
- [ ] Save device-gate log per `docs/analysis/device-gates/*.md` format
- [ ] Save profile.conf and profile.bin used
- [ ] Run cmp_disasm against baseline
- [ ] Document result in plan or review record

---

## 8.1 fd_graph Profile Template (Target Content)

```hocon
# GhostLock kernel profile: 6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k (HOCON).
# route = fd_graph. Built from extractor output + preload.so geometry constants.
# STATUS: UNVERIFIED — requires device gate.
include "credential-6x.conf"
include "kernelsnitch-6x.conf"
release = "6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k"
schema_version = 1
kernel_major = 6
recommend_shizuku = 0
kernel_phys_load = 2147418112
kernel_phys_offset = 2147483648
route {
  fd_graph {
    eventpoll_size = 208
    epitem_ep = 72
    epitem_fllink = 80
    pipe_buffer = 40
    pipe_flags = 24
    pipe_slots = 32
    pipe_ring = 1280
    pipe_object = 2048
    graph_width = 96
    graph_fanout = 256
    graph_edges = 24576
    objects_per_order3 = 16
  }
}
fallback {
  to = "none"
}
task_struct {
  prio = 148
  normal_prio = 156
  sched_task_group = 1056
  pi_lock = 2540
  pi_waiters = 2560
  pi_top_task = 2576
  pi_blocked_on = 2584
  pid = 1800
  tgid = 1804
  atomic_flags = 1736
  real_cred = 2296
  cred = 2304
  comm = 2320
  tasks = 1592
  seccomp = 2504
}
cred {
  caps_offset = 48
  copy_size = 136
  usage_value = 1
  caps_count = 5
  caps_value = -1
}
offset {
  init_task = 39049920
  init_cred = 39139376
  empty_zero_page = 41349120
  root_task_group = 41384128
  selinux_enforcing = 41707872
  selinux_blob_sizes = 26441832
  security_hook_heads = 0
  slide_nfulnl_logger = 39002544
  slide_loggers_0_1 = 39002368
  slide_boot_id = 41848136
  off_vr_sys_exit_tp = 40734048
}
vr_guard {
  funcs_offset = 72
  tag_b_off = 44
}
```

**Note**: All fd_graph geometry values from preload.so .rodata (decimal). task_struct/cred/offset/vr_guard from existing verified profile. Physical addresses from mtk-phys.sh (2026-10-02).

---

## 9. 원자적 커밋 전략 (Atomic Commit Strategy)

### 9.1 Commit 1: CLI Route Support (S-level)
```bash
git add tools/extract_rs/src/main.rs
git commit -m "feat(extract): add fd_graph to --route CLI choices"
```

### 9.2 Commit 2: fd_graph Profile (L-level)
```bash
git add app/src/main/assets/kernel_profiles/6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k.conf
git commit -m "feat(profile): 6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k fd_graph route

- Switch from select_stack (infeasible) to fd_graph middleware
- Add 12 fd_graph geometry constants from preload.so reference exploit
- Preserve verified task_struct, cred, offset, vr_guard, physical addresses
- Status: UNVERIFIED — pending device gate"
```

### 9.3 Commit 3: Device Gate Evidence (Post-Validation)
```bash
git add docs/analysis/device-gates/V2514-fd_graph-<date>.md
git commit -m "docs(device-gate): V2514 fd_graph route validation <date>

- Cold boot, CPU 0+1, KernelSU unloaded
- W1/W2/W3 PASS, root_child handoff, KernelSU module loaded
- cmp_disasm: 8 functions IDENTICAL"
```

---

## 10. 위험 요소 및 완화 (Risks & Mitigations)

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| fd_graph geometry constants from preload.so don't match this kernel | Medium | Device panic / W1 fail | Preload.so verified on same device/kernel; constants are structural (struct sizes) not KASLR-dependent |
| Extractor missing required symbols (task_struct, cred) | Low | Profile incomplete | Extractor analysis mode will report; manual fallback to existing profile values |
| Physical addresses stale (kernel update) | Low | Address translation error | Re-run mtk-phys.sh on device before validation |
| cmp_disasm shows unexpected differences | Medium | Attack path regression | Compare only 8 core attack functions; annotate expected differences (route switch) |
| KernelSU module load fails after handoff | Low | Root but no module | Verify ksud running; check vr_guard bypass (already in profile) |

---

## 11. 의존성 그래프 (Dependency Graph)

```
Phase 0 (Prep)
  └─> Phase 1 (Extraction)
        ├─> Phase 2a (Profile Construction) ──> Phase 3 (Native Build)
        │                                         │
        │                                         └─> Phase 4 (Device Validation)
        │                                               │
        │                                               └─> Phase 5 (Archival)
        │
        └─> Phase 2b (CLI Route Fix) ──> Phase 3
```

**Critical Path**: Phase 0 → Phase 1 → Phase 2a → Phase 3 → Phase 4 → Phase 5

**Parallelizable**: Phase 2b (CLI fix) can run anytime after Phase 0.

---

## 12. 성공 기준 (Success Criteria)

1. **Build**: All build verification commands (§6.1) pass
2. **Profile**: `exportKernelProfiles` generates `.bin`; `BuiltinProfilesTest` passes
3. **Device**: Single cold-boot run shows:
   - Log: `route = fd_graph` with all 12 geometry constants non-zero
   - W1: `selinux_enforcing` written 0 → verified
   - W2: `cred` swapped → uid 0 verified
   - W3: seccomp filter bypassed
   - Handoff: `root_child` spawns → `ksud` loads KernelSU module
   - `su -c id` returns `uid=0(root)`
4. **Disassembly**: `cmp_disasm` shows IDENTICAL for 8 attack functions (or reviewed diffs)
5. **Evidence**: Device-gate log archived per documentation standards

---

## 13. 다음 단계 (Next Steps for Execution)

1. **Confirm plan** with user — review fd_graph constants, physical addresses, risk acceptance
2. **Execute Phase 0-1** — extraction and analysis
3. **Review extracted offsets** — compare with existing profile, note gaps
4. **Execute Phase 2-3** — profile write + native build
5. **Execute Phase 4** — device validation (requires physical device access)
6. **Execute Phase 5** — evidence archival

---

**Plan Author**: opencode (nemotron-3-ultra-free)  
**Date**: 2026-10-03  
**Classification**: L-level (attack critical path change — route switch)  
**Requires User Approval**: Yes — before Phase 2 profile overwrite