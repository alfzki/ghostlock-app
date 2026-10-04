#ifndef FD_GRAPH_ROUTE_H
#define FD_GRAPH_ROUTE_H

#include "memory/payload_builder.h"
#include "profile/model.h"
#include "route/route_status.h"
#include "support/native_resource.hpp"

#include <atomic>
#include <cstdint>

namespace ghostlock::route::fd_graph {

inline constexpr uint64_t kFdGraphGenmark0 = 0x304b52414d4e4547ULL;

[[nodiscard]] constexpr bool fd_graph_mode_needs_bit4(
    ghostlock::memory::WriteMode mode) noexcept {
    return mode != ghostlock::memory::WriteMode::Zero;
}

[[nodiscard]] constexpr bool fd_graph_can_merge_set(uint8_t flags_byte) noexcept {
    return (flags_byte & 0x10) != 0;
}

[[nodiscard]] constexpr bool fd_graph_genmark_changed(uint64_t observed) noexcept {
    return observed != kFdGraphGenmark0;
}

[[nodiscard]] constexpr bool fd_graph_round_success(bool zero_mode, bool chain_hit,
                                                    bool bit4) noexcept {
    return zero_mode ? chain_hit : (chain_hit && bit4);
}

[[nodiscard]] constexpr uint64_t fd_graph_table_high(uint64_t page, uint32_t index) noexcept {
    return page + 0x100 + static_cast<uint64_t>(index) * 0x800;
}

[[nodiscard]] constexpr bool fd_graph_cmd_accepted(char reply) noexcept {
    return reply == 'W';
}

[[nodiscard]] constexpr bool fd_graph_enforce_pass(char enforce_byte) noexcept {
    return enforce_byte != '1';
}

class FdGraphRoute final {
public:
    FdGraphRoute(const ghostlock::memory::WriteRequest *route_request,
                 const ghostlock::profile::TargetProfile &profile_value,
                 ghostlock::profile::FdGraphLayout route_layout) noexcept;

    ~FdGraphRoute() noexcept = default;

    FdGraphRoute(const FdGraphRoute &) = delete;
    FdGraphRoute &operator=(const FdGraphRoute &) = delete;

    FdGraphRoute(FdGraphRoute &&other) noexcept
        : request(other.request),
          profile(other.profile),
          layout(other.layout),
          epoll_fd(std::move(other.epoll_fd)),
          pipe_read(std::move(other.pipe_read)),
          pipe_write(std::move(other.pipe_write)),
          consumer_thread(std::move(other.consumer_thread)),
          pipe_worker(std::move(other.pipe_worker)),
          epoll_fds(std::move(other.epoll_fds)),
          reclaim_table(std::move(other.reclaim_table)),
          drain_table(std::move(other.drain_table)),
          staging_buffer(std::move(other.staging_buffer)),
          consumer_stuck(other.consumer_stuck),
          calls(other.calls),
          successes(other.successes),
          reclaim_hits(other.reclaim_hits),
          chain_hits(other.chain_hits),
          bit4_hits(other.bit4_hits),
          round(other.round),
          status(other.status) {
        stop_consumer.store(false, std::memory_order_relaxed);
        other.stop_consumer.store(false, std::memory_order_relaxed);
    }

    [[nodiscard]] int32_t prepare() noexcept;

    [[nodiscard]] ghostlock::route::RouteStatus execute() noexcept;

    void disarm() noexcept;

    void destroy() noexcept;

    [[nodiscard]] int32_t fail(int32_t step, int32_t error_number) noexcept;

    const ghostlock::memory::WriteRequest *request = nullptr;
    const ghostlock::profile::TargetProfile &profile;
    ghostlock::profile::FdGraphLayout layout{};
    ghostlock::support::UniqueFd epoll_fd;
    ghostlock::support::UniqueFd pipe_read;
    ghostlock::support::UniqueFd pipe_write;
    ghostlock::support::PthreadOwner consumer_thread;
    ghostlock::support::PthreadOwner pipe_worker;
    ghostlock::support::BulkFdOwner epoll_fds;
    ghostlock::support::MappedRegion reclaim_table;
    ghostlock::support::MappedRegion drain_table;
    ghostlock::support::MappedRegion staging_buffer;
    int32_t consumer_stuck = 0;
    int32_t calls = 0;
    int32_t successes = 0;
    uint32_t reclaim_hits = 0;
    uint32_t chain_hits = 0;
    uint32_t bit4_hits = 0;
    uint32_t round = 0;
    std::atomic<bool> stop_consumer{false};
    ghostlock::route::RouteStatus status{};

private:
    void retain_for_process_lifetime() noexcept;
};

// Entry point called by FdGraphPolicy::run()
ghostlock::route::RouteStatus do_fd_graph_fake_lock_route(const ghostlock::memory::WriteRequest *request);

} // namespace ghostlock::route::fd_graph

#endif