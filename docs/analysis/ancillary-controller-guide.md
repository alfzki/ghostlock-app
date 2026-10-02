# Ancillary behavior guide (`AncillaryController`)

Audience: the developer implementing the `vr.ko` behavior and their agent.

This document describes **the architecture and how to adapt a behavior to it**. The
concrete `vr.ko` bypass logic, its parameters and their verification are **not**
described here on purpose — they are agreed in the pull-request discussion.

---

## 1. What the controller is

`AncillaryController` hosts behaviors that run **outside the vulnerability path**:
vendor anti-root mitigations, environment fixups and similar. It is deliberately
separate from the `frontend × backend × middleware` component axes:

- those axes describe the **exploit path** (the primitive and how a kernel write is
  realized);
- an ancillary behavior describes **extra steps around that path** and must not change
  how the path writes.

Project-wide constraints apply (`../../AGENTS.md`): compile-time composition, no virtual
dispatch, no mutable globals, and configuration is never inferred from the kernel
version.

## 2. Where the pieces live

| Path | Role |
|---|---|
| `../../src/core/session/ancillary/ancillary_policy.hpp` | `AncillaryKind`, `AncillaryStage`, `AncillaryContext`, `AncillaryPolicyDefaults`, and the `AncillaryPolicyFor` concept |
| `../../src/core/session/ancillary/ancillary_controller.hpp` | the `AncillaryPolicyList` registry and the header-only dispatcher `AncillaryController<Middleware>::apply` |
| `../../src/core/session/ancillary/ancillary_controller.cpp` | Android translation unit that pulls the header through the device build |
| `../../src/core/session/ancillary/vr_guard.hpp` | the `vr.ko` behavior (`VrGuardPolicy`) |
| `../../src/core/tests/ancillary_test.cpp` | host test for the registry, the profile gate and the dispatch signature |

## 3. The behavior contract

A behavior is a policy type satisfying `AncillaryPolicyFor<P, Middleware>`:

- `static constexpr AncillaryKind kind` — a stable id (append one to the enum);
- `static bool enabled(const profile::TargetProfile &)` — the profile gate. Fail
  closed: if the resolved profile does not enable the behavior, return `false`;
- `template <class Middleware> static Status apply(AncillaryStage, ExploitSession &, AncillaryContext &)` — the stage entry.

`AncillaryStage` selects **when** the behavior runs relative to the exploit steps:
`PreSpawn` (setup done, before a victim exists), `PostSpawn` (a victim exists),
`PreHandoff` (before the frontend handoff). `AncillaryContext` carries what the backend
injects: whether the kernel write primitive and the read-back primitive are available,
plus the runtime applicability decision (§5).

## 4. Adding a behavior — the only touch points

1. Append an id to `AncillaryKind`.
2. Create `src/core/session/ancillary/<name>.hpp` (and `.cpp` when the body needs the
   device/attack primitives):
   - keep the **plan** — pure functions that turn the resolved profile layout and
     already-read values into an ordered list of writes — in the header; it must be
     host-compilable and unit-tested with fixed vectors;
   - keep the **execution** — anything that touches the kernel — in the `.cpp`, using
     the primitives injected through `AncillaryContext`.
3. Append the policy type to `AncillaryPolicyList` in `ancillary_controller.hpp`.
   **This is the single registration point.** No route, frontend or backend edits.
4. Add a host test and register it in `../../src/Makefile`.
5. Add the behavior's profile contract on both sides (§6).

The backend calls `AncillaryController<Middleware>::apply` at the fixed stages; that
call site is wired **once** and never changes when behaviors are added.

## 5. Applicability is a runtime decision

`enabled()` is only a **pre-set from the profile**. It is not proof that the behavior
is relevant on the running device:

- the same GKI release is shipped by multiple vendors, so the kernel string / release
  is **not** a device identity;
- therefore a behavior that targets a vendor component must **confirm at runtime** that
  the component is actually present, and **do nothing** when it is not (fail safe);
- record that decision in `AncillaryContext` at the controller entry, not in the route.

Do not key a behavior on `uname -r` or on the profile release. The profile gate and the
runtime applicability are two separate facts and both must hold.

## 6. Profile contract (GLK1 v2)

Behavior configuration travels in the resolved profile, never in environment variables
(`../../AGENTS.md`):

- a **gate** field records whether the support list enables the behavior for this
  profile;
- an optional **layout** section carries the behavior-specific parameters;
- shared kernel symbol offsets live in the existing `offset` section.

Add the fields to the native model (`profile/model.h`, `profile/binary.cpp`) and mirror
them in `profile-core` (`NativeProfile.kt`, the resolver, the exporter and the app-side
injection); the key names must match verbatim and the golden fixtures must be
recomputed. The exact field set for `vr.ko` is defined by the PR, not by this document.

## 7. Constraints checklist

- [ ] No mutable global state; do not add fields to `ExploitSession` — its layout is
      fixed so attack-function stack offsets do not move.
- [ ] No indirect/virtual dispatch on the attack path.
- [ ] Header-only parts compile on the host.
- [ ] New code is warning-free under `-Wall -Wextra -Wconversion -Wsign-conversion`.
- [ ] Configuration comes from the profile; no configuration-class environment
      variables.

## 8. Verification

- `make -C src native-host-tests`
- NDK build with **zero warnings**
- `make -C src lint-tidy`
- If the behavior touches the attack path: `python3 tools/cmp_disasm.py <baseline> build/native/ghostlock`
  **and** the on-device gate (cold boot, fixed CPU pair, single route, KernelSU not
  loaded), archived under `docs/analysis/device-gates/`.

## 9. The `vr.ko` behavior

> **Verification status: UNVERIFIED on hardware.** The policy is implemented and
> host-tested, but it has never executed on a device. `PreSpawn` runs strictly
> after `w1()` returns `Continue`
> (`session/backend/cve_2026_43499_backend.cpp:458-484`), so on any release
> whose W1 is blocked the guard is unreachable — including
> `6.12.58-android16-6`, where all three W1 routes fail. No device log in this
> repository contains `vr.ko sys_exit probe neutralized`; the only occurrences
> are the expected log lines in `docs/development/tcp-zerocopy-6x-plan.md`.
> Treat the writes below as correct by construction and host test, not as
> demonstrated. Per `AGENTS.md`, nothing here may be reported as supported
> until a cold-boot device gate produces that log with
> `ro.boot.bootreason != kernel_panic`.

`VrGuardPolicy` (id `VrGuard`) is the first registered behavior, and it is implemented. It
neutralizes the vivo/iQOO `vr.ko` anti-root mitigation in two layers, because the module
both tags every app-origin task and arms a global `sys_exit` tracepoint probe:

| Stage | Layer | Write |
|---|---|---|
| `PreSpawn` | global | zero `funcs` in `vr`'s `__tracepoint_sys_exit` (protects the root shells and `ksud`) |
| `PostSpawn` | per-task | zero the `thread_info.flags` word, then tag B (protects the exploit child across W2 verify) |

**Tagging scheme** (derived from `vr.ko` disassembly, compile-time constants in
`vr_guard.hpp`): tag A at `task_struct+0x06`, tag B at `task_struct+0x2c`, the
syscall-tracepoint flag `0x400` in `thread_info.flags`. The exploit write primitive is
64-bit granular, so tag A and the flag bit are cleared by the single `thread_info.flags`
word at `task_struct+0x00`; only tag B needs a byte-granular write, hence only its offset
is configurable. Two `static_assert`s keep both inside the word the plan zeroes.

**Profile contract** — the `vr_guard` section, all fields optional (the section is omitted
when the profile does not configure it, so every other profile's wire bytes are unchanged):

| Key | Type | Meaning |
|---|---|---|
| `enabled` | u8 | the support-list gate; absent or 0 means the behavior never runs |
| `funcs_offset` | u32 | `offsetof(struct tracepoint, funcs)` for the running KMI (0x40 on 6.1, 0x48 on 6.6) |
| `tag_b_off` | u32 | offset of vr tag B in `task_struct` |

The symbol offset stays in the shared `offset` section as `off_vr_sys_exit_tp`, because it
is a plain symbol offset rather than a behavior parameter.

Write the values in **decimal**. The resolver reads each field as a number (`getLongAt`),
and a hex literal such as `0x40` does not survive parsing as one: the field resolves to
"absent", is dropped from the wire, and the behavior silently turns itself off. `0x40` is
`64`, `0x2c` is `44`; the hex forms in the table describe the value, not the syntax.

**`funcs_offset` is never derived from the release string.** A previous revision inferred
it from `uname -r` (6.1 → `0x40`, 6.6 → `0x48`), which §5 forbids; it is now profile data.

**Applicability is still a runtime decision.** `enabled` is only a pre-set. At each stage
the behavior reads `/proc/modules` and records the outcome in `AncillaryContext::component_present`,
doing nothing when `vr.ko` is absent. An **unreadable** `/proc/modules` counts as *present*,
not absent: SELinux normally hides that file from an unprivileged app, so "cannot read"
carries no information and treating it as absent would silently disable the bypass on exactly
the devices that need it. What actually restricts the behavior is the profile gate plus a
non-zero `off_vr_sys_exit_tp`. The probe result is deliberately not cached in a
function-local `static` (§7 forbids new mutable globals; one small proc read per stage is
free).

### Storage: why the layout is not in `kernel_offsets`

§7 forbids growing `ExploitSession`, whose layout is fixed so attack-function stack offsets
do not move. `kernel_offsets` is embedded in `TargetProfile`, which is embedded in
`ExploitSession`, so adding `VrGuardLayout` there grew the session by 16 bytes and moved
every member after `profile` — measurably, and enough to change the machine code of the
gated attack functions.

So `vr_guard` follows the same rule as `binary_profile::component_ids`: it decodes into a
**side output** (`profile::vr_guard_layout`, threaded through `binary_profile::parse` and
the `profile_entry::read_glk1_*` readers) and is published once at startup into
`profile::g_vr_guard_layout`, which is read-only afterwards — the same category as the
existing `kernel::g_direct_map_end`. `sizeof(ExploitSession)` stays 1648 and every session
member offset is unchanged.

Consequence to remember when adding the next side-output section: a new file-scope global
renumbers data addresses, so `cmp_disasm.py` will report `OPERAND-DIFF` on the gated
functions even though the instruction count and the layout-normalised disassembly are
identical. That is a reviewed annotated difference, not a regression; verify it with the
instruction-count and layout columns rather than the tool's exit code alone.

### Review findings from the vr.ko pull request

PR #221 carried an automated review whose findings are the agreed contract for this
behavior; the four open items and how this implementation answers them:

| # | Finding | Resolution |
|---|---|---|
| 1 | HIGH: do not guess the tracepoint `funcs` offset from the kernel minor | `funcs_offset` is profile data. The release-keyed `tracepoint_funcs_off()` (6.1 -> `0x40`, 6.6+ -> `0x48`) is deleted, along with the `TRACEPOINT_FUNCS_OFF_*` constants it used |
| 2 | MED: assume loaded when `/proc/modules` cannot be opened | `vr_module_loaded()` returns true when `fopen` fails; only a successful scan that finds no `vr` entry clears the flag |
| 3 | MED: handle neutralization failure before spawning W2 | `PreSpawn` failure returns `StageResult::Failed` (`RunCode::Failed`), instead of warning and continuing into a chain whose child the still-armed probe would kill |
| 4 | MED: the extractor must emit the new offset in `--format conf` | The key was in `conf_offsets()` but missing from `CONF_OFFSET_FIELDS`, so `render_conf` dropped it and every generated profile left the runtime offset at 0. Added there, with test coverage on both the emitted and the omitted case |

Finding 4 is worth remembering: `conf_offsets()` producing a key proves nothing, because
`render_conf` re-projects its output through the separate `CONF_OFFSET_FIELDS` allowlist.
A key can be computed, filtered out, and rendered as `null` without any error.

### No read-back verification

`AncillaryContext::read_available` is part of the behavior contract, but nothing sets it
and no behavior reads it: the write primitive is the only kernel capability injected
today. Both layers therefore trust the write primitive's own verification, whereas the
reference implementation (CyberMeowfia `c87b866`) reads the bytes back and asserts the
result on each layer. Adding that needs a read primitive exposed through the context,
which is new attack-path surface and belongs in its own reviewed change with a device
gate — not folded in here.

### What is still unverified

`cmp_disasm.py` covers six of the eight gated functions — `multicast_owner_worker` and
`multicast_waiter_worker` are not present in the symbols of an NDK release build, in the
baseline as well as in the candidate. The on-device gate (cold boot, fixed CPU pair, single
route, KernelSU not loaded) is still required before this behavior may be called verified.
