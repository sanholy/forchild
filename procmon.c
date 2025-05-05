#define _GNU_SOURCE
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sched.h>

#define PROC_INFO_BUF_SIZE 4096
#define MAX_CACHE_ENTRIES 1024
#define CACHE_TTL_SECONDS 10
#define MAX_RETRIES 10
#define FAST_RETRY_DELAY_US 300
#define PRELOAD_CACHE_SIZE 32
#define MAX_EVENTS 32
#define PROC_PATH_MAX 40

struct Event {
    unsigned event_type;
    pid_t pid, ppid, tgid;
};

struct ProcInfo {
    char cwd[PROC_INFO_BUF_SIZE];
    char exe[PROC_INFO_BUF_SIZE];
    char cmdline[PROC_INFO_BUF_SIZE];
};

struct ProcessCache {
    pid_t pid;
    time_t last_update;
    int status;
    pid_t ppid;
    pid_t tgid;
    char name[256];           // 新增：进程名
    char cwd[PROC_INFO_BUF_SIZE]; // 新增：进程工作目录
    char exe[PROC_INFO_BUF_SIZE];
    char cmdline[PROC_INFO_BUF_SIZE];
};

static struct ProcessCache process_cache[MAX_CACHE_ENTRIES];
static pid_t preload_cache[PRELOAD_CACHE_SIZE] = {0};
static int preload_index = 0;
static volatile sig_atomic_t running = 1;

static void increase_priority() {
    setpriority(PRIO_PROCESS, 0, -10);
    struct sched_param param = {.sched_priority = 10};
    sched_setscheduler(0, SCHED_FIFO, &param);
}

static void handle_signal(int sig) {
    running = 0;
}

static inline int is_safe_char(char c) {
    return (c >= 0x20 && c <= 0x7E) || (c & 0x80);
}

static void enhanced_trim(char *str) {
    if (!str || !*str) return;
    
    char *end = str + strlen(str) - 1;
    while (end > str && !is_safe_char(*end)) end--;
    *(end + 1) = '\0';

    while (*str && !is_safe_char(*str)) str++;
    if (str != str) memmove(str, str, end - str + 1);
}

static void get_proc_path(char *buf, pid_t pid, const char *file) {
    snprintf(buf, PROC_PATH_MAX, "/proc/%d/%s", pid, file);
}

static int read_proc_file(pid_t pid, const char *file, char *buf, size_t size) {
    char path[PROC_PATH_MAX];
    get_proc_path(path, pid, file);
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) return -1;
    
    ssize_t n = read(fd, buf, size-1);
    close(fd);
    
    if (n > 0) {
        buf[n] = '\0';
        return 0;
    }
    return -1;
}

static int read_proc_cmdline(pid_t pid, char *buf, size_t size) {
    char path[PROC_PATH_MAX];
    get_proc_path(path, pid, "cmdline");
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) return -1;
    
    ssize_t n = read(fd, buf, size-1);
    close(fd);
    
    if (n <= 0) return -1;

    buf[n] = '\0';
    
    for (int i = 0; i < n; i++) {
        if (buf[i] == '\0') {
            if (i < n-1) {
                buf[i] = ' ';
            } else {
                buf[i] = '\0';
            }
        }
    }
    
    buf[size-1] = '\0';
    return 0;
}

static int is_process_alive(pid_t pid) {
    char path[PROC_PATH_MAX];
    get_proc_path(path, pid, "status");
    return access(path, F_OK) == 0;
}

static const char *get_proc_name_cached(pid_t pid) {
    static const char *unknown = "?";
    time_t now = time(NULL);
    
    // 查找缓存
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (process_cache[i].pid == pid) {
            if (process_cache[i].name[0] != '\0') {
                process_cache[i].last_update = now;
                return process_cache[i].name;
            }
            break;
        }
    }
    
    // 缓存未命中，读取proc文件
    char path[PROC_PATH_MAX];
    get_proc_path(path, pid, "stat");
    
    FILE *fp = fopen(path, "r");
    if (!fp) return unknown;
    
    char name[256] = {0};
    if (fscanf(fp, "%*d (%255[^)])", name) != 1) {
        fclose(fp);
        return unknown;
    }
    fclose(fp);
    
    // 存入缓存
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (process_cache[i].pid == pid || process_cache[i].pid == 0) {
            if (process_cache[i].pid == 0) {
                process_cache[i].pid = pid;
            }
            strncpy(process_cache[i].name, name, sizeof(process_cache[i].name)-1);
            process_cache[i].last_update = now;
            return process_cache[i].name;
        }
    }
    
    return unknown;
}

static void update_cache(pid_t pid, int status, pid_t ppid, pid_t tgid, 
                       const char *name, const char *cwd, const char *exe, const char *cmdline) {
    time_t now = time(NULL);
    int empty_slot = -1;

    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (process_cache[i].pid == pid) {
            process_cache[i].status = status;
            process_cache[i].last_update = now;
            process_cache[i].ppid = ppid;
            process_cache[i].tgid = tgid;
            if (name) strncpy(process_cache[i].name, name, sizeof(process_cache[i].name)-1);
            if (cwd) strncpy(process_cache[i].cwd, cwd, sizeof(process_cache[i].cwd)-1);
            if (exe) strncpy(process_cache[i].exe, exe, sizeof(process_cache[i].exe)-1);
            if (cmdline) strncpy(process_cache[i].cmdline, cmdline, sizeof(process_cache[i].cmdline)-1);
            return;
        }
        if (empty_slot == -1 && process_cache[i].pid == 0) {
            empty_slot = i;
        }
    }

    if (empty_slot != -1) {
        process_cache[empty_slot].pid = pid;
        process_cache[empty_slot].status = status;
        process_cache[empty_slot].last_update = now;
        process_cache[empty_slot].ppid = ppid;
        process_cache[empty_slot].tgid = tgid;
        if (name) strncpy(process_cache[empty_slot].name, name, sizeof(process_cache[empty_slot].name)-1);
        if (cwd) strncpy(process_cache[empty_slot].cwd, cwd, sizeof(process_cache[empty_slot].cwd)-1);
        if (exe) strncpy(process_cache[empty_slot].exe, exe, sizeof(process_cache[empty_slot].exe)-1);
        if (cmdline) strncpy(process_cache[empty_slot].cmdline, cmdline, sizeof(process_cache[empty_slot].cmdline)-1);
    }
}

static void cleanup_cache() {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (process_cache[i].pid != 0 && 
            process_cache[i].status == 0 && 
            (now - process_cache[i].last_update) > CACHE_TTL_SECONDS) {
            memset(&process_cache[i], 0, sizeof(struct ProcessCache));
        }
    }
}

static int get_proc_info_aggressive(pid_t pid, struct ProcInfo *info) {
    memset(info, 0, sizeof(*info));
    
    char path[PROC_PATH_MAX];
    struct stat st;
    int retries = 0;
    
    get_proc_path(path, pid, "exe");
    while (retries < MAX_RETRIES) {
        if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {
            ssize_t len = readlink(path, info->exe, sizeof(info->exe)-1);
            if (len > 0) {
                info->exe[len] = '\0';
                char *deleted = strstr(info->exe, " (deleted)");
                if (deleted) *deleted = '\0';
                break;
            }
        }
        
        if (!is_process_alive(pid)) break;
        usleep(FAST_RETRY_DELAY_US);
        retries++;
    }
    
    get_proc_path(path, pid, "cwd");
    if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {
        readlink(path, info->cwd, sizeof(info->cwd)-1);
    }

    if (read_proc_cmdline(pid, info->cmdline, sizeof(info->cmdline)) != 0) {
        get_proc_path(path, pid, "comm");
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(info->cmdline, sizeof(info->cmdline), f)) {
                info->cmdline[strcspn(info->cmdline, "\n")] = '\0';
            }
            fclose(f);
        } else if (info->exe[0] != '\0') {
            const char *base = strrchr(info->exe, '/');
            strncpy(info->cmdline, base ? base+1 : info->exe, sizeof(info->cmdline)-1);
        }
    }
    
    enhanced_trim(info->cmdline);
    
    // 更新缓存中的信息
    update_cache(pid, 0, 0, 0, 
                get_proc_name_cached(pid), // 获取进程名
                info->cwd, 
                info->exe, 
                info->cmdline);
    
    return (info->exe[0] != '\0') ? 0 : -1;
}

static void get_timestamp(char *buf, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm);
    snprintf(buf + strlen(buf), size - strlen(buf), ".%09ld", ts.tv_nsec);
}

static pid_t get_ppid_from_stat(pid_t pid) {
    char path[PROC_PATH_MAX];
    get_proc_path(path, pid, "stat");
    
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char buf[2048];
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    char *end_comm = strrchr(buf, ')');
    if (!end_comm) return -1;

    char *p = end_comm + 1;
    p += strspn(p, " ");
    p += strcspn(p, " ");
    p += strspn(p, " ");

    return atoi(p);
}

static void traceback_pids(pid_t pid, char *trace_buf, size_t buf_size) {
    char tmp[128];
    pid_t current_pid = pid;
    int depth = 0;
    const int max_depth = 10;
    
    trace_buf[0] = '\0';
    
    while (depth < max_depth) {
        pid_t ppid = get_ppid_from_stat(current_pid);
        if (ppid <= 0) break;
        
        const char *proc_name = get_proc_name_cached(current_pid);
        
        snprintf(tmp, sizeof(tmp), "%d(%s)->", current_pid, proc_name);
        strncat(trace_buf, tmp, buf_size - strlen(trace_buf) - 1);
        
        current_pid = ppid;
        depth++;
    }
    
    if (depth > 0) {
        const char *proc_name = get_proc_name_cached(current_pid);
        snprintf(tmp, sizeof(tmp), "%d(%s)", current_pid, proc_name);
        strncat(trace_buf, tmp, buf_size - strlen(trace_buf) - 1);
    }
}

static int nl_connect() {
    int nl_sock = socket(PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK, NETLINK_CONNECTOR);
    if (nl_sock == -1) return -1;

    int rcvbuf_size = 2 * 1024 * 1024;
    setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid = getpid()
    };

    if (bind(nl_sock, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        close(nl_sock);
        return -1;
    }
    return nl_sock;
}

static int set_proc_ev_listen(int nl_sock, bool enable) {
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg msg;
            enum proc_cn_mcast_op op;
        };
    } packet = {
        .hdr = {
            .nlmsg_len = sizeof(packet),
            .nlmsg_pid = getpid(),
            .nlmsg_type = NLMSG_DONE
        },
        .msg = {
            .id = { CN_IDX_PROC, CN_VAL_PROC },
            .len = sizeof(enum proc_cn_mcast_op)
        },
        .op = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE
    };

    return send(nl_sock, &packet, sizeof(packet), 0) == -1 ? -1 : 0;
}

static int handle_proc_ev(int nl_sock, struct Event *ev) {
    struct __attribute__((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr hdr;
        struct __attribute__((__packed__)) {
            struct cn_msg msg;
            struct proc_event proc_ev;
        };
    } packet;

    ssize_t ret = recv(nl_sock, &packet, sizeof(packet), MSG_DONTWAIT);
    if (ret <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    *ev = (struct Event){
        .event_type = packet.proc_ev.what,
        .pid = 0,
        .ppid = 0,
        .tgid = 0
    };

    switch (packet.proc_ev.what) {
    case PROC_EVENT_FORK:
        ev->pid = packet.proc_ev.event_data.fork.child_pid;
        ev->ppid = packet.proc_ev.event_data.fork.parent_pid;
        ev->tgid = packet.proc_ev.event_data.fork.child_tgid;
        break;
    case PROC_EVENT_EXEC:
        ev->pid = packet.proc_ev.event_data.exec.process_pid;
        ev->tgid = packet.proc_ev.event_data.exec.process_tgid;
        break;
    case PROC_EVENT_EXIT:
        ev->pid = packet.proc_ev.event_data.exit.process_pid;
        ev->tgid = packet.proc_ev.event_data.exit.process_pid;
        break;
    }
    return 1;
}

int main() {
    increase_priority();
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    int nl_sock = nl_connect();
    if (nl_sock < 0) {
        fprintf(stderr, "Error: Failed to initialize netlink socket\n");
        return EXIT_FAILURE;
    }

    if (set_proc_ev_listen(nl_sock, true) < 0) {
        fprintf(stderr, "Error: Failed to subscribe to process events\n");
        close(nl_sock);
        return EXIT_FAILURE;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(nl_sock);
        return EXIT_FAILURE;
    }

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = nl_sock };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nl_sock, &ev) == -1) {
        perror("epoll_ctl");
        close(epoll_fd);
        close(nl_sock);
        return EXIT_FAILURE;
    }

    printf("Ultimate Process Monitor Started (Press Ctrl+C to exit)...\n");

    struct epoll_event events[MAX_EVENTS];
    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 100);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == nl_sock) {
                struct Event ev;
                while (handle_proc_ev(nl_sock, &ev) > 0) {
                    char timestamp[32];
                    get_timestamp(timestamp, sizeof(timestamp));

                    switch (ev.event_type) {
                    case PROC_EVENT_FORK:
                        preload_cache[preload_index++ % PRELOAD_CACHE_SIZE] = ev.pid;
                        update_cache(ev.pid, 1, ev.ppid, ev.tgid, NULL, NULL, NULL, NULL);
                        break;

                    case PROC_EVENT_EXEC: {
                        int is_preloaded = 0;
                        for (int i = 0; i < PRELOAD_CACHE_SIZE; i++) {
                            if (preload_cache[i] == ev.pid) {
                                is_preloaded = 1;
                                preload_cache[i] = 0;
                                break;
                            }
                        }

                        struct ProcInfo process_info;
                        int ret = get_proc_info_aggressive(ev.pid, &process_info);
                        
                        pid_t spid = ev.tgid;
                        pid_t ppid = 0;
                        struct ProcInfo parent_info = {0};

                        if (ev.pid == ev.tgid) {
                            ppid = get_ppid_from_stat(ev.pid);
                            if (ppid > 0) {
                                spid = ppid;
                                get_proc_info_aggressive(spid, &parent_info);
                            }
                        } else {
                            get_proc_info_aggressive(spid, &parent_info);
                        }

                        for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
                            if (process_cache[i].pid == ev.pid) {
                                if (process_info.exe[0] == '\0' && process_cache[i].exe[0] != '\0') {
                                    strncpy(process_info.exe, process_cache[i].exe, sizeof(process_info.exe)-1);
                                }
                                if (process_info.cmdline[0] == '\0' && process_cache[i].cmdline[0] != '\0') {
                                    strncpy(process_info.cmdline, process_cache[i].cmdline, sizeof(process_info.cmdline)-1);
                                }
                                break;
                            }
                        }

                        char traceback[256] = {0};
                        traceback_pids(ev.pid, traceback, sizeof(traceback));

                        printf("[%s] spid=%d sexe=%s scmd=%s scwd=%s dpid=%d dexe=%s dcmd=%s dcwd=%s traceback=%s\n",
                            timestamp,
                            spid,
                            parent_info.exe[0] ? parent_info.exe : "?",
                            parent_info.cmdline[0] ? parent_info.cmdline : "?",
                            parent_info.cwd[0] ? parent_info.cwd : "?",

                            ev.pid, 
                            process_info.exe[0] ? process_info.exe : "?", 
                            process_info.cmdline[0] ? process_info.cmdline : "?",
                            process_info.cwd[0] ? process_info.cwd : "?",
                            traceback);

                        update_cache(ev.pid, 2, ppid, ev.tgid, 
                                    get_proc_name_cached(ev.pid),
                                    process_info.cwd,
                                    process_info.exe, 
                                    process_info.cmdline);
                        break;
                    }
                    case PROC_EVENT_EXIT:
                        update_cache(ev.pid, 0, 0, 0, NULL, NULL, NULL, NULL);
                        break;
                    }
                    fflush(stdout);
                }
            }
        }
        cleanup_cache();
    }

    set_proc_ev_listen(nl_sock, false);
    close(epoll_fd);
    close(nl_sock);
    return EXIT_SUCCESS;
}
