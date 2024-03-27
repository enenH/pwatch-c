#include <iostream>
#include <functional>
#include <vector>
#include <array>
#include <thread>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdio>
#include <dirent.h>
#include <asm-generic/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/perf_regs.h>
#include <sys/mman.h>
#include <poll.h>

static int perf_event_open(struct perf_event_attr *evt_attr, pid_t pid,
                           int cpu, int group_fd, unsigned long flags) {
    int ret;
    ret = syscall(__NR_perf_event_open, evt_attr, pid, cpu, group_fd, flags);
    return ret;
}

static std::vector<int> GetProcessTask(int pid) {
    std::vector<int> vOutput;
    DIR *dir = nullptr;
    struct dirent *ptr = nullptr;
    char szTaskPath[256] = {0};
    sprintf(szTaskPath, "/proc/%d/task", pid);

    dir = opendir(szTaskPath);
    if (nullptr != dir) {
        while ((ptr = readdir(dir)) != nullptr) // 循环读取路径下的每一个文件/文件夹
        {
            // 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
            if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
                continue;
            } else if (ptr->d_type != DT_DIR) {
                continue;
            } else if (strspn(ptr->d_name, "1234567890") != strlen(ptr->d_name)) {
                continue;
            }

            int task = atoi(ptr->d_name);
            char buff[1024];
            sprintf(buff, "/proc/%d/task/%d/comm", pid, task);
            FILE *fp = fopen(buff, "r");
            if (fp) {
                char name[1024]{0};
                fgets(name, sizeof(name), fp);
                fclose(fp);
                std::string_view sv(name);
                const char *blacklist[] = {
                    "RenderThread",
                    "FinalizerDaemon",
                    "RxCachedThreadS",
                    "mali-cmar-backe",
                    "mali-utility-wo",
                    "mali-mem-purge",
                    "mali-hist-dump",
                    "mali-event-hand",
                    "hwuiTask0",
                    "hwuiTask1",
                    "NDK MediaCodec_",
                };
                for (auto &i: blacklist) {
                    if (sv.find(i) != std::string_view::npos) {
                        continue;
                    }
                }
                if (sv.starts_with("binder:") || sv.starts_with("twitter")) {
                    continue;
                }
                /*   LOGD("task %d %s", task, name);*/
                vOutput.push_back(task);
            }
        }
        closedir(dir);
    }
    return vOutput;
}

struct SampleData {
    uint32_t pid;
    uint32_t tid;
    uint64_t abi;
    std::array<uint64_t, PERF_REG_ARM64_MAX> regs;
};

class PerfMap {
    int _fd = 0;
    void *_mmap_addr = nullptr;
    size_t _mmap_size = 0;

public:
    void create(int pid, uintptr_t bp_addr, int bp_type, size_t bp_len, int buf_size = 0) {
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

        int fd = perf_event_open(&attr, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd < 0) {
            perror("perf_event_open error");
            return;
        }
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        _mmap_size = (1 + (1 << buf_size)) * PAGE_SIZE;
        void *buff = mmap(nullptr, _mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        _mmap_addr = buff;
        _fd = fd;
    }

    void process(const std::function<void(const SampleData &)> &handle, const bool *loop = nullptr) {
        auto mmap_page_metadata = (perf_event_mmap_page *) _mmap_addr;
        auto data_addr = (uintptr_t) _mmap_addr + mmap_page_metadata->data_offset;
        auto data_size = mmap_page_metadata->data_size;
        auto read_data_size = 0;

        pollfd perf_poll{};
        perf_poll.fd = _fd;
        perf_poll.events = POLLIN;

        while (loop == nullptr || *loop) {
            if (poll(&perf_poll, 1, -1) < 0) {
                perror("poll() failed!");
                break;
            }

            while (mmap_page_metadata->data_head != read_data_size) {
                auto get_addr = [data_addr, read_data_size, data_size](int offset) {
                    return data_addr + ((read_data_size + offset) % data_size);
                };
                auto data_header = (perf_event_header *) get_addr(0);
                auto offset = sizeof(perf_event_header);
                if (data_header->type == PERF_RECORD_SAMPLE) {
                    auto pid = *(uint32_t *) get_addr(offset);
                    offset += 4;
                    auto tid = *(uint32_t *) get_addr(offset);
                    offset += 4;
                    auto abi = *(uint64_t *) get_addr(offset);
                    offset += 8;
                    auto regs = std::array<uint64_t, PERF_REG_ARM64_MAX>();
                    for (auto &reg: regs) {
                        reg = *(uint64_t *) get_addr(offset);
                        offset += 8;
                    }
                    auto data = SampleData{
                        pid,
                        tid,
                        abi,
                        regs
                    };
                    handle(data);
                } else if (data_header->type == PERF_RECORD_LOST) {
                    auto lost = *(uint64_t *) get_addr(offset);
                    std::cout << "-------" << std::endl;
                    std::cout << "Lost " << lost << " events" << std::endl;
                } else {
                    std::cout << "-------" << std::endl;
                    std::cout << "Unknown type" << std::endl;
                }
                read_data_size += data_header->size;
                mmap_page_metadata->data_tail = read_data_size;
            }
        }
    }

    void destroy() {
        if (_fd) {
            ioctl(_fd,PERF_EVENT_IOC_DISABLE, 0);
            close(_fd);
            _fd = 0;
        }
        if (_mmap_addr) {
            munmap(_mmap_addr, _mmap_size);
            _mmap_addr = nullptr;
        }
    }
};


int main() {
    auto tasks = GetProcessTask(31001);
    for (auto &task: tasks) {
        std::cout << "task: " << task << std::endl;
    }
    for (auto &task: tasks) {
        pthread_t t;
        pthread_create(&t, nullptr, [](void *arg) -> void *{
            static const std::string regNames[] = {
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
                "pc", "pstate"
            };

            PerfMap perfMap;
            perfMap.create(*(int *) arg, 0x7AF5A7D750, HW_BREAKPOINT_X, HW_BREAKPOINT_LEN_4);
            perfMap.process([&](const SampleData &data) {
                std::cout << "pid: " << data.pid << "tid: " << data.tid << " abi: " << data.abi << std::endl;
                std::string message;
                for (int i = 0; i < data.regs.size(); i++) {
                    message += regNames[i] + ": " + std::to_string(data.regs[i]) + "|";
                }
                std::cout << message << std::endl;
                std::cout << "---------------------------" << std::endl;
            });
            perfMap.destroy();
            return nullptr;
        }, &task);
    }
    sleep(5);
    return 0;
}
