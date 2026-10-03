#ifndef GHOSTLOCK_PROFILE_H
#define GHOSTLOCK_PROFILE_H

#include <cstddef>
#include <cstdint>

#include <array>
#include <cstring>
#include <optional>
#include <string_view>
#include <utility>

namespace ghostlock::profile {
    /* PROFILE-SUGGEST-01: only kernel geometry (kernel_major, symbol and struct
     * offsets, waiter layout, credential template) is truly required. Kotlin merges
     * the shipped execution defaults and user overrides before the profile reaches
     * native; see docs/kernel_profiles/defaults*.md. */
    struct execution_settings {
        uint32_t recommended_main_cpu, recommended_consumer_cpu;
        uint32_t heap_prepare_max_attempts, heap_prepare_timeout_ms;
        uint32_t heap_kernelsnitch_timeout_ms;
        uint32_t race_route_wait_ms, race_route_done_timeout_ms;
        uint32_t race_setup_settle_us;
        uint32_t race_state_poll_interval_us;
        uint32_t w1_attempts, w1_settle_us, w1_scratch_repair_attempts;
        uint32_t w2_attempts, w2_settle_us;
        uint32_t w3_chain_rounds, w3_attempts, w3_settle_us;
        uint32_t tcp_attempts, tcp_arm_sequence;
        uint32_t tcp_post_receive_hold_iterations;
        uint32_t select_enter_delay_us, select_timeout_us;
        uint32_t select_consumer_max_calls, select_consumer_burst_calls;
        uint32_t handoff_pre_dispatch_settle_ms, handoff_module_poll_attempts;
        uint32_t handoff_module_poll_interval_ms, handoff_enforce_poll_attempts;
        uint32_t handoff_enforce_poll_interval_ms;
    };


    /* Explicit route selection written by the profile ("route": "<name>").
     * Geometry inference below exists only for profiles predating the field. */
    enum class RouteKind : uint8_t {
        Auto = 0,
        TcpZerocopy = 1,
        SelectStack = 2,
        MulticastWaiter = 3,
        FdGraph = 4,
    };

    /* Wire values for the v2 binary transport and the v1 JSON converter. */
    inline constexpr uint8_t kRouteAuto = std::to_underlying(RouteKind::Auto);
    inline constexpr uint8_t kRouteTcpZerocopy =
            std::to_underlying(RouteKind::TcpZerocopy);
    inline constexpr uint8_t kRouteSelectStack =
            std::to_underlying(RouteKind::SelectStack);
    inline constexpr uint8_t kRouteMulticastWaiter =
            std::to_underlying(RouteKind::MulticastWaiter);
    inline constexpr uint8_t kRouteFdGraph =
            std::to_underlying(RouteKind::FdGraph);

    /* Single native route catalog: token <-> wire value. Adding a route means
     * one entry here plus its RoutePolicy / procedure. */
    struct RouteCatalogEntry {
        std::string_view token;
        uint8_t wire;
    };

    inline constexpr RouteCatalogEntry kRouteCatalog[] = {
        {"tcp_zerocopy", kRouteTcpZerocopy},
        {"select_stack", kRouteSelectStack},
        {"multicast_waiter", kRouteMulticastWaiter},
        {"fd_graph", kRouteFdGraph},
    };

    [[nodiscard]] inline uint8_t route_kind_from_string(std::string_view name) {
        for (const RouteCatalogEntry &entry : kRouteCatalog) {
            if (name == entry.token) return entry.wire;
        }
        return kRouteAuto;
    }

    /* Wire v2 model objects, one per transport section. Signedness/width mirror
     * Kotlin (uint8_t->UByte, uint32_t->UInt, uint64_t->ULong, int32_t->Int).
     * Fields with a runtime fallback are std::optional: absence means "not
     * provided", distinct from a provided 0 (kernel_phys_load = 0 is
     * meaningful). The wire carries presence by key occurrence. */
    struct ProfileMeta {
        uint8_t kernel_major = 0;
        uint8_t recommend_shizuku = 0;
        uint8_t fallback_route = 0;
        uint8_t safe_mode = 0;
    };

    struct TaskStructOffsets {
        uint32_t prio = 0, normal_prio = 0, sched_task_group = 0;
        uint32_t pi_lock = 0, pi_waiters = 0, pi_top_task = 0, pi_blocked_on = 0;
        uint32_t pid = 0, tgid = 0, atomic_flags = 0;
        uint32_t real_cred = 0, cred = 0, comm = 0, tasks = 0, seccomp = 0;
    };

    struct CredTemplate {
        uint32_t copy_size = 0, usage_offset = 0, usage_value = 0;
        uint32_t caps_offset = 0, caps_count = 0;
        uint64_t caps_value = 0;
        uint32_t ref_count = 0;
        uint32_t ref0_offset = 0, ref1_offset = 0, ref2_offset = 0, ref3_offset = 0;
        uint64_t ref0_image = 0, ref1_image = 0, ref2_image = 0, ref3_image = 0;
    };

    struct KernelOffsets {
        uint64_t init_task = 0, init_cred = 0, empty_zero_page = 0;
        uint64_t root_task_group = 0, selinux_enforcing = 0;
        uint64_t selinux_blob_sizes = 0, security_hook_heads = 0;
        uint64_t slide_nfulnl_logger = 0, slide_loggers_0_1 = 0, slide_boot_id = 0, off_vr_sys_exit_tp = 0;
    };

    /* vivo vr.ko anti-root guard (AncillaryKind::VrGuard). The gate says the
     * support list enables the behavior for this profile; the layout carries the
     * behavior's own parameters. The kernel symbol offset stays in the shared
     * `offset` section (`off_vr_sys_exit_tp`) because it is a plain symbol
     * offset, not a behavior parameter.
     *
     * Deliberately NOT a member of kernel_offsets: that struct is embedded in
     * TargetProfile, which is embedded in ExploitSession, whose layout is fixed
     * so attack-function stack offsets do not move (same reason
     * binary_profile::component_ids is kept out). Every field is optional, so a
     * profile that does not configure the behavior omits the section and its
     * wire bytes stay identical. */
    struct vr_guard_layout {
        std::optional<uint8_t> enabled;
        /* offsetof(struct tracepoint, funcs) for the running KMI. */
        std::optional<uint32_t> funcs_offset;
        /* Offset of vr tag B in task_struct (tag A and the syscall-tracepoint
         * bit live inside the thread_info flags word, so they need no field). */
        std::optional<uint32_t> tag_b_off;
    };

    /* Decoded once at startup next to the profile, then read-only for the rest of
     * the process (the same category as kernel::g_direct_map_end). Written only
     * by main() from the decode side output; the vr.ko behavior is its only
     * reader. */
    extern vr_guard_layout g_vr_guard_layout;

    struct KernelMisc {
        std::optional<uint64_t> kernel_phys_load;
        /* DRAM base (linear-map PHYS_OFFSET) used for image->direct-map
         * translation. Absence falls back to the compiled P0_PHYS_OFFSET, so
         * devices whose DRAM base differs from the built-in default can
         * override it without a rebuild. */
        std::optional<uint64_t> kernel_phys_offset;
        std::optional<uint8_t> compact_waiter;
        std::optional<uint32_t> kernelsnitch_collisions;
        std::optional<uint32_t> mm_struct_sz;
        // fd_graph route geometry (from preload.so .rodata strings)
        std::optional<uint32_t> eventpoll_size;
        std::optional<uint32_t> epitem_ep;
        std::optional<uint32_t> epitem_fllink;
        std::optional<uint32_t> pipe_buffer;
        std::optional<uint32_t> pipe_flags;
        std::optional<uint32_t> pipe_slots;
        std::optional<uint32_t> pipe_ring;
        std::optional<uint32_t> pipe_object;
        std::optional<uint32_t> graph_width;
        std::optional<uint32_t> graph_fanout;
        std::optional<uint32_t> graph_edges;
        std::optional<uint32_t> objects_per_order3;
    };

    struct RouteGeometry {
        std::optional<int32_t> pselect_waiter_shift;
        std::optional<int32_t> mcast_waiter_off;
        std::optional<uint32_t> mcast_buffer_size;
        std::optional<uint32_t> mcast_task_offset;
        std::optional<uint32_t> mcast_lock_offset;
    };

    /* Native transport representation of one Kotlin-resolved profile. */
    struct kernel_offsets {
        const char *uname_r;
        uint8_t route;
        ProfileMeta meta;
        TaskStructOffsets task;
        CredTemplate credential;
        KernelOffsets offsets;
        KernelMisc misc;
        RouteGeometry geometry;
        struct execution_settings execution;

        /* Typed view of the wire route field so callers need no cast. */
        [[nodiscard]] RouteKind route_kind() const noexcept {
            return static_cast<RouteKind>(route);
        }
    };

    struct MulticastWaiterLayout {
        std::optional<int32_t> waiter_offset;
        std::optional<uint32_t> buffer_size, task_offset, lock_offset;
    };

    struct SelectStackLayout {
        std::optional<int32_t> waiter_shift;
        std::optional<uint8_t> compact_waiter;
    };

    struct TcpZerocopyLayout {
        std::optional<uint8_t> compact_waiter;
    };

    struct FdGraphLayout {
        std::optional<uint32_t> eventpoll_size;
        std::optional<uint32_t> epitem_ep;
        std::optional<uint32_t> epitem_fllink;
        std::optional<uint32_t> pipe_buffer;
        std::optional<uint32_t> pipe_flags;
        std::optional<uint32_t> pipe_slots;
        std::optional<uint32_t> pipe_ring;
        std::optional<uint32_t> pipe_object;
        std::optional<uint32_t> graph_width;
        std::optional<uint32_t> graph_fanout;
        std::optional<uint32_t> graph_edges;
        std::optional<uint32_t> objects_per_order3;
    };


    /* Immutable runtime snapshot copied from the transport representation.
     * The C++ value owns uname_r and rebinds the transport pointer after every
     * copy/move. The C layout remains available as a compatibility façade. */
    class TargetProfile final {
    public:
        TargetProfile() noexcept = default;

        explicit TargetProfile(const struct kernel_offsets &transport) noexcept
            : values_(transport), loaded_(true) {
            copy_release(transport.uname_r);
        }

        TargetProfile(const TargetProfile &other) noexcept
            : values_(other.values_), release_(other.release_),
              loaded_(other.loaded_) {
            rebind_release();
        }

        TargetProfile &operator=(const TargetProfile &other) noexcept {
            if (this != &other) {
                values_ = other.values_;
                release_ = other.release_;
                loaded_ = other.loaded_;
                rebind_release();
            }
            return *this;
        }

        /* Delegates to the copy constructor on purpose: rebinds the release buffer
       * and keeps the moved-from profile valid for the process-wide accessor. */
        TargetProfile(TargetProfile &&other) noexcept
            : TargetProfile(other) { // NOLINT(performance-move-constructor-init)
        }

        TargetProfile &operator=(TargetProfile &&other) noexcept {
            return *this = other;
        }

        [[nodiscard]] const struct kernel_offsets *values() const noexcept {
            return loaded_ ? &values_ : nullptr;
        }

        [[nodiscard]] bool loaded() const noexcept { return loaded_; }

        [[nodiscard]] RouteKind route() const noexcept {
            return loaded_ ? static_cast<RouteKind>(values_.route) : RouteKind::Auto;
        }

        [[nodiscard]] RouteKind fallback_route() const noexcept {
            return loaded_ ? static_cast<RouteKind>(values_.meta.fallback_route) : RouteKind::Auto;
        }

        [[nodiscard]] bool supports(RouteKind kind) const noexcept {
            return route() == kind;
        }

        [[nodiscard]] const char *release() const noexcept {
            return loaded_ && values_.uname_r ? values_.uname_r : "";
        }

        [[nodiscard]] const struct execution_settings *execution() const noexcept {
            return loaded_ ? &values_.execution : nullptr;
        }

        [[nodiscard]] uint64_t off_vr_sys_exit_tp() const noexcept {
            return loaded_ ? values_.offsets.off_vr_sys_exit_tp : 0;
        }

        /* Typed execution-config getters. Every execution field is an unsigned
         * 32-bit value both in `execution_settings` and on the wire (the legacy
         * JSON parser also rejects negatives), so each getter returns uint32_t
         * and no static_cast is required at the call site. */
#define GHOSTLOCK_EXEC_U32(name) \
        [[nodiscard]] uint32_t name() const noexcept { return values_.execution.name; }
        GHOSTLOCK_EXEC_U32(recommended_main_cpu)
        GHOSTLOCK_EXEC_U32(recommended_consumer_cpu)
        GHOSTLOCK_EXEC_U32(heap_prepare_max_attempts)
        GHOSTLOCK_EXEC_U32(heap_prepare_timeout_ms)
        GHOSTLOCK_EXEC_U32(heap_kernelsnitch_timeout_ms)
        GHOSTLOCK_EXEC_U32(race_route_wait_ms)
        [[nodiscard]] uint32_t race_route_done_timeout_ms() const noexcept {
            constexpr uint32_t kDefaultRouteDoneTimeoutMs = 300000;
            return or_default(values_.execution.race_route_done_timeout_ms,
                              kDefaultRouteDoneTimeoutMs);
        }
        GHOSTLOCK_EXEC_U32(race_setup_settle_us)
        GHOSTLOCK_EXEC_U32(race_state_poll_interval_us)
        GHOSTLOCK_EXEC_U32(w1_attempts)
        GHOSTLOCK_EXEC_U32(w1_settle_us)
        GHOSTLOCK_EXEC_U32(w1_scratch_repair_attempts)
        GHOSTLOCK_EXEC_U32(w2_attempts)
        GHOSTLOCK_EXEC_U32(w2_settle_us)
        GHOSTLOCK_EXEC_U32(w3_chain_rounds)
        GHOSTLOCK_EXEC_U32(w3_attempts)
        GHOSTLOCK_EXEC_U32(w3_settle_us)
        GHOSTLOCK_EXEC_U32(tcp_attempts)
        GHOSTLOCK_EXEC_U32(tcp_arm_sequence)
        GHOSTLOCK_EXEC_U32(tcp_post_receive_hold_iterations)
        GHOSTLOCK_EXEC_U32(select_enter_delay_us)
        GHOSTLOCK_EXEC_U32(select_timeout_us)
        GHOSTLOCK_EXEC_U32(select_consumer_max_calls)
        GHOSTLOCK_EXEC_U32(select_consumer_burst_calls)
        GHOSTLOCK_EXEC_U32(handoff_pre_dispatch_settle_ms)
        GHOSTLOCK_EXEC_U32(handoff_module_poll_attempts)
        GHOSTLOCK_EXEC_U32(handoff_module_poll_interval_ms)
        GHOSTLOCK_EXEC_U32(handoff_enforce_poll_attempts)
        GHOSTLOCK_EXEC_U32(handoff_enforce_poll_interval_ms)
#undef GHOSTLOCK_EXEC_U32

        [[nodiscard]] bool has_compact_waiter() const noexcept {
            return loaded_ && values_.misc.compact_waiter.value_or(0) != 0;
        }

        [[nodiscard]] bool safe_mode() const noexcept {
            return loaded_ && values_.meta.safe_mode;
        }

        [[nodiscard]] MulticastWaiterLayout multicast_layout() const noexcept {
            return loaded_
                       ? (MulticastWaiterLayout){
                           .waiter_offset = values_.geometry.mcast_waiter_off,
                           .buffer_size = values_.geometry.mcast_buffer_size,
                           .task_offset = values_.geometry.mcast_task_offset,
                           .lock_offset = values_.geometry.mcast_lock_offset,
                       }
                       : MulticastWaiterLayout{};
        }

        [[nodiscard]] SelectStackLayout select_stack_layout() const noexcept {
            return loaded_
                       ? (SelectStackLayout){
                           .waiter_shift = values_.geometry.pselect_waiter_shift,
                           .compact_waiter = values_.misc.compact_waiter,
                       }
                       : SelectStackLayout{};
        }

        [[nodiscard]] TcpZerocopyLayout tcp_zerocopy_layout() const noexcept {
            return (TcpZerocopyLayout){.compact_waiter = values_.misc.compact_waiter};
        }

        [[nodiscard]] FdGraphLayout fd_graph_layout() const noexcept {
            return loaded_
                       ? (FdGraphLayout){
                           .eventpoll_size = values_.misc.eventpoll_size,
                           .epitem_ep = values_.misc.epitem_ep,
                           .epitem_fllink = values_.misc.epitem_fllink,
                           .pipe_buffer = values_.misc.pipe_buffer,
                           .pipe_flags = values_.misc.pipe_flags,
                           .pipe_slots = values_.misc.pipe_slots,
                           .pipe_ring = values_.misc.pipe_ring,
                           .pipe_object = values_.misc.pipe_object,
                           .graph_width = values_.misc.graph_width,
                           .graph_fanout = values_.misc.graph_fanout,
                           .graph_edges = values_.misc.graph_edges,
                           .objects_per_order3 = values_.misc.objects_per_order3,
                       }
                       : FdGraphLayout{};
        }

        [[nodiscard]] uint32_t or_default(uint32_t value, uint32_t fallback)
        const noexcept {
            return (loaded_ && value) ? value : fallback;
        }

        [[nodiscard]] uint32_t mm_struct_stride(uint32_t fallback) const noexcept {
            return or_default(loaded_ ? values_.misc.mm_struct_sz.value_or(0) : 0, fallback);
        }

        [[nodiscard]] uint64_t image(uint64_t offset, uint64_t image_base,
                                     uint64_t fallback_offset) const noexcept {
            return image_base + ((loaded_ && offset) ? offset : fallback_offset);
        }

        static TargetProfile from(const struct kernel_offsets *values) {
            return values ? TargetProfile(*values) : TargetProfile();
        }

    private:
        void copy_release(const char *release) noexcept {
            release_.fill('\0');
            if (release) {
                const size_t length = std::strlen(release);
                const size_t copied =
                        length < release_.size() ? length : release_.size() - 1;
                std::memcpy(release_.data(), release, copied);
            }
            rebind_release();
        }

        void rebind_release() noexcept {
            values_.uname_r = loaded_ ? release_.data() : nullptr;
        }

        struct kernel_offsets values_{};
        std::array<char, 256> release_{};
        bool loaded_ = false;
    };
} // namespace ghostlock::profile

#endif
