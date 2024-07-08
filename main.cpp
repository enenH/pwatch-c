#include <iostream>
#include <vector>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdio>
#include <dirent.h>
#include <pthread.h>
#include <sstream>

#include "PerfMap.h"

static std::vector<int> GetProcessTask(int pid) {
    std::vector<int> vOutput;
    DIR* dir = nullptr;
    struct dirent* ptr = nullptr;
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
            FILE* fp = fopen(buff, "r");
            if (fp) {
                char name[1024]{0};
                fgets(name, sizeof(name), fp);
                fclose(fp);
                std::string_view sv(name);
                const char* blacklist[] = {
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
                for (auto& i : blacklist) {
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

static const std::string regNames[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "lr", "sp",
    "pc", "max"
};

int main() {
    pthread_t t;
    pthread_create(&t, nullptr, [](void*) -> void* {
        const auto tasks = GetProcessTask(28944);
        for (auto& task : tasks) {
            std::cout << "task: " << task << std::endl;
        }
        PerfMap perfMap;
        perfMap.create(tasks, 0x73EF915AD4, HW_BREAKPOINT_X, HW_BREAKPOINT_LEN_4, 4);
        perfMap.process([&](const SampleData& data) {
            std::cout << "pid: " << data.pid << " tid: " << data.tid << " abi: " << data.abi << std::endl;
            std::string message;
            for (int i = 0; i < PERF_REG_ARM64_MAX; i++) {
                std::stringstream ss;
                ss << std::hex << data.regs[i];
                message += regNames[i] + ": 0x" + ss.str() + "|";
            }
            std::cout << message << std::endl;
            std::cout << "---------------------------" << std::endl;
        });
        perfMap.destroy();
        return nullptr;
    }, nullptr);

    sleep(5);
    return 0;
}
