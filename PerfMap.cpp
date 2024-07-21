#include "PerfMap.h"

#include <cstdio>
#include <iostream>
#include <poll.h>
#include <asm-generic/unistd.h>
#include <bits/ioctl.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <unistd.h>

static int perf_event_open(struct perf_event_attr* evt_attr, pid_t pid,
                           int cpu, int group_fd, unsigned long flags) {
    int ret;
    ret = syscall(__NR_perf_event_open, evt_attr, pid, cpu, group_fd, flags);
    return ret;
}

int PerfMap::create(const std::vector<int>& pids, uintptr_t bp_addr, int bp_type, size_t bp_len, int buf_size) {
    perf_event_attr attr{};
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.watermark = 0;
    attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.precise_ip = 2; //同步

    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    attr.bp_type = bp_type;
    attr.bp_addr = bp_addr;
    attr.bp_len = bp_len;

    attr.sample_regs_user = ((1ULL << PERF_REG_ARM64_MAX) - 1);
    attr.mmap = 1;
    attr.comm = 1;
    attr.mmap_data = 1;
    attr.mmap2 = 1;

    for (int pid : pids) {
        PerfInfo info{};
        int fd = perf_event_open(&attr, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd < 0) {
            printf("%d perf_event_open error %s\n", pid, strerror(errno));
            continue;
        }
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        info.fd = fd;
        info.mmap_size = (1 + (1 << buf_size)) * PAGE_SIZE;
        info.mmap_addr = mmap(nullptr, info.mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (info.mmap_addr == MAP_FAILED) {
            printf("%d mmap error %s\n", pid, strerror(errno));
            close(fd);
            continue;
        }
        _perf_infos.push_back(info);
    }
    return 0;
}

void PerfMap::process(const std::function<void(const SampleData&)>& handle, const bool* loop) {
    if (_perf_infos.empty()) {
        printf("No perf event to process\n");
        return;
    }
    pollfd perf_poll[_perf_infos.size()];

    for (int i = 0; i < _perf_infos.size(); i++) {
        auto& info = _perf_infos[i];
        info.mmap_page_metadata = (perf_event_mmap_page*)info.mmap_addr;
        info.data_addr = (uintptr_t)info.mmap_addr + info.mmap_page_metadata->data_offset;
        info.read_data_size = 0;
        info.data_size = info.mmap_page_metadata->data_size;
        perf_poll[i].fd = info.fd;
        perf_poll[i].events = POLLIN;
    }

    while (loop == nullptr || *loop) {
        //每两秒退出一下 防止卡死
        int ret = poll(perf_poll, _perf_infos.size(), 2000);
        if (ret <= 0) {
            continue;
        }
        for (int i = 0; i < _perf_infos.size(); i++) {
            auto& info = _perf_infos[i];
            if (perf_poll[i].revents & POLLIN) {
                while (info.mmap_page_metadata->data_head != info.read_data_size) {
                    auto get_addr = [&](size_t offset) {
                        return info.data_addr + ((info.read_data_size + offset) % info.data_size);
                    };
                    auto data_header = (perf_event_header*)get_addr(0);
                    auto offset = sizeof(perf_event_header);
                    if (data_header->type == PERF_RECORD_SAMPLE) {
                        auto pid = *(uint32_t*)get_addr(offset);
                        offset += 4;
                        auto tid = *(uint32_t*)get_addr(offset);
                        offset += 4;
                        auto abi = *(uint64_t*)get_addr(offset);
                        offset += 8;

                        SampleData data{};
                        for (unsigned long& reg : data.regs) {
                            reg = *(uint64_t*)get_addr(offset);
                            offset += 8;
                        }
                        data.pid = pid;
                        data.tid = tid;
                        data.abi = abi;
                        handle(data);
                        if (loop != nullptr && *loop == false) {
                            return;
                        }
                    }
#ifndef NDEBUG
                    else if (data_header->type == PERF_RECORD_LOST) {
                        auto lost = *(uint64_t*)get_addr(offset);
                        std::cout << "-------" << std::endl;
                        std::cout << "Lost " << lost << " events" << std::endl;
                    } else {
                        std::cout << "-------" << std::endl;
                        std::cout << "Unknown type" << std::endl;
                    }
#endif
                    info.read_data_size += data_header->size;
                    info.mmap_page_metadata->data_tail = info.read_data_size;
                }
            }
        }
    }
}

void PerfMap::enable() {
    for (auto& info : _perf_infos) {
        ioctl(info.fd, PERF_EVENT_IOC_ENABLE, 0);
    }
}

void PerfMap::disable() {
    for (auto& info : _perf_infos) {
        ioctl(info.fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(info.fd, PERF_EVENT_IOC_DISABLE, 0);
    }
}

void PerfMap::destroy() {
    for (auto& info : _perf_infos) {
        if (info.fd) {
            ioctl(info.fd, PERF_EVENT_IOC_DISABLE, 0);
            close(info.fd);
        }
        if (info.mmap_addr) {
            munmap(info.mmap_addr, info.mmap_size);
        }
    }
    _perf_infos.clear();
}
