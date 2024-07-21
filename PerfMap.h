#pragma once
#include <cstdint>
#include <functional>
#include <asm/perf_regs.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
struct SampleData {
    uint32_t pid;
    uint32_t tid;
    uint64_t abi;
    uint64_t regs[PERF_REG_ARM64_MAX];
};

class PerfMap {
    struct PerfInfo {
        int pid = 0;
        int fd = 0;
        void* mmap_addr = nullptr;

        size_t mmap_size = 0;
        perf_event_mmap_page* mmap_page_metadata = nullptr;
        uintptr_t data_addr = 0;
        uintptr_t data_size = 0;
        int read_data_size = 0;
    };

    std::vector<PerfInfo> _perf_infos;

public:
    int create(const std::vector<int>& pids, uintptr_t bp_addr, int bp_type, size_t bp_len, int buf_size = 0);

    void process(const std::function<void(const SampleData&)>& handle, const bool* loop = nullptr);

    void enable();

    void disable();

    void destroy();
};
