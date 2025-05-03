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
#include <sys/timerfd.h>
#include <inttypes.h>

#define PROC_INFO_BUF_SIZE 4096
#define MAX_CACHE_ENTRIES 1024
#define CACHE_TTL_SECONDS 10
#define MAX_RETRIES 3
#define RETRY_DELAY_MS 5

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
    int status; // 0=exit, 1=fork, 2=exec
    pid_t ppid;
    pid_t tgid;
    char exe[PROC_INFO_BUF_SIZE];
    char cmdline[PROC_INFO_BUF_SIZE];
};

static struct ProcessCache process_cache[MAX_CACHE_ENTRIES];
static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
    running = 0;
}

static int is_safe_char(char c) {
    return isprint((unsigned char)c) && !isspace((unsigned char)c);
}

static void enhanced_trim(char *str) {
    if (!str) return;
    
    char *end = str + strlen(str);
    while (end > str && !is_safe_char(*(end-1))) end--;
    *end = '\0';

    char *start = str;
    while (*start && !is_safe_char(*start)) start++;
    memmove(str, start, end - start + 1);
}

static int read_proc_file(pid_t pid, const char *file, char *buf, size_t size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, file);
    
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

static int get_proc_info_with_retry(pid_t pid, struct ProcInfo *info, int retries) {
    memset(info, 0, sizeof(*info));
    
    for (int i = 0; i < retries; i++) {
        // Get cwd
        char path[PATH_MAX];
        struct stat st;
        snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
        if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {
            readlink(path, info->cwd, sizeof(info->cwd)-1);
        }

        // Get exe (most important for exec events)
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        if (lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) {
            ssize_t len = readlink(path, info->exe, sizeof(info->exe)-1);
            if (len > 0) {
                info->exe[len] = '\0';
                char *deleted = strstr(info->exe, " (deleted)");
                if (deleted) *deleted = '\0';
            }
        }

        // Get cmdline (may be empty for very short-lived processes)
        if (read_proc_file(pid, "cmdline", info->cmdline, sizeof(info->cmdline)) == 0) {
            for (size_t i = 0; i < strlen(info->cmdline); i++) {
                if (info->cmdline[i] == '\0') info->cmdline[i] = ' ';
            }
        }

        // If we got at least the exe path, consider it successful
        if (info->exe[0] != '\0') {
            enhanced_trim(info->cmdline);
            return 0;
        }

        if (i < retries - 1) {
            struct timespec delay = {0, RETRY_DELAY_MS * 1000000};
            nanosleep(&delay, NULL);
        }
    }
    return -1;
}

static void get_timestamp(char *buf, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm);
    snprintf(buf + strlen(buf), size - strlen(buf), ".%09ld", ts.tv_nsec);
}

static pid_t get_ppid_from_stat(pid_t pid) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

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

static void update_cache(pid_t pid, int status, pid_t ppid, pid_t tgid, 
                         const char *exe, const char *cmdline) {
    time_t now = time(NULL);
    int empty_slot = -1;

    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (process_cache[i].pid == pid) {
            process_cache[i].status = status;
            process_cache[i].last_update = now;
            process_cache[i].ppid = ppid;
            process_cache[i].tgid = tgid;
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

static void traceback_pids(pid_t pid, char *trace_buf, size_t buf_size) {
    char tmp[32];
    pid_t current_pid = pid;
    int depth = 0;
    const int max_depth = 10;
    
    trace_buf[0] = '\0';
    
    while (depth < max_depth) {
        pid_t ppid = get_ppid_from_stat(current_pid);
        if (ppid <= 0) break;
        
        snprintf(tmp, sizeof(tmp), "%d->", current_pid);
        strncat(trace_buf, tmp, buf_size - strlen(trace_buf) - 1);
        
        current_pid = ppid;
        depth++;
    }
    
    if (depth > 0) {
        snprintf(tmp, sizeof(tmp), "%d", current_pid);
        strncat(trace_buf, tmp, buf_size - strlen(trace_buf) - 1);
    }
}

static int nl_connect() {
    int nl_sock = socket(PF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK, NETLINK_CONNECTOR);
    if (nl_sock == -1) return -1;

    // Increase receive buffer size
    int rcvbuf_size = 256 * 1024;
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

    // Set up epoll for non-blocking I/O
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(nl_sock);
        return EXIT_FAILURE;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = nl_sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, nl_sock, &ev) == -1) {
        perror("epoll_ctl");
        close(epoll_fd);
        close(nl_sock);
        return EXIT_FAILURE;
    }

    printf("Process Monitor Started (Press Ctrl+C to exit)...\n");

    struct epoll_event events[1];
    while (running) {
        int nfds = epoll_wait(epoll_fd, events, 1, 100); // 100ms timeout
        if (nfds == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        cleanup_cache();

        if (nfds > 0) {
            struct Event ev;
            while (handle_proc_ev(nl_sock, &ev) > 0) {
                char timestamp[32];
                get_timestamp(timestamp, sizeof(timestamp));

                switch (ev.event_type) {
                case PROC_EVENT_FORK: {
                    struct ProcInfo parent_info, child_info;
                    get_proc_info_with_retry(ev.ppid, &parent_info, MAX_RETRIES);
                    get_proc_info_with_retry(ev.pid, &child_info, MAX_RETRIES);

                    char traceback[256];
                    traceback_pids(ev.pid, traceback, sizeof(traceback));

                    printf("[%s] etype=fork parent=%d pcwd=\"%s\" pexe=\"%s\" pcmd=\"%s\" "
                           "child=%d ccwd=\"%s\" cexe=\"%s\" ccmd=\"%s\" traceback=\"%s\"\n",
                           timestamp,
                           ev.ppid, parent_info.cwd, parent_info.exe, parent_info.cmdline,
                           ev.pid, child_info.cwd, child_info.exe, child_info.cmdline,
                           traceback);

                    update_cache(ev.pid, 1, ev.ppid, ev.tgid, child_info.exe, child_info.cmdline);
                    break;
                }
                case PROC_EVENT_EXEC: {
                    struct ProcInfo process_info;
                    int ret = get_proc_info_with_retry(ev.pid, &process_info, MAX_RETRIES);
                    
                    pid_t spid = ev.tgid;
                    pid_t ppid = 0;
                    struct ProcInfo parent_info;

                    if (ev.pid == ev.tgid) {
                        ppid = get_ppid_from_stat(ev.pid);
                        if (ppid > 0) {
                            spid = ppid;
                            get_proc_info_with_retry(spid, &parent_info, MAX_RETRIES);
                        }
                    }

                    // Fallback to cache if we couldn't get process info
                    if (ret != 0 || process_info.exe[0] == '\0') {
                        for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
                            if (process_cache[i].pid == ev.pid && process_cache[i].status != 0) {
                                if (process_info.exe[0] == '\0' && process_cache[i].exe[0] != '\0') {
                                    strncpy(process_info.exe, process_cache[i].exe, sizeof(process_info.exe)-1);
                                }
                                if (process_info.cmdline[0] == '\0' && process_cache[i].cmdline[0] != '\0') {
                                    strncpy(process_info.cmdline, process_cache[i].cmdline, sizeof(process_info.cmdline)-1);
                                }
                                break;
                            }
                        }
                    }

                    char traceback[256];
                    traceback_pids(ev.pid, traceback, sizeof(traceback));

                    printf("[%s] etype=exec parent=%d pcwd=\"%s\" pexe=\"%s\" pcmd=\"%s\" "
                           "process=%d cwd=\"%s\" exe=\"%s\" cmd=\"%s\" traceback=\"%s\"\n",
                           timestamp,
                           spid, parent_info.cwd, parent_info.exe, parent_info.cmdline,
                           ev.pid, process_info.cwd, process_info.exe, process_info.cmdline,
                           traceback);

                    update_cache(ev.pid, 2, ppid, ev.tgid, process_info.exe, process_info.cmdline);
                    break;
                }
                case PROC_EVENT_EXIT: {
                    struct ProcInfo process_info;
                    update_cache(ev.pid, 0, 0, 0, NULL, NULL);
                    break;
                }
                }
                fflush(stdout);
            }
        }
    }

    set_proc_ev_listen(nl_sock, false);
    close(epoll_fd);
    close(nl_sock);
    return EXIT_SUCCESS;
}
