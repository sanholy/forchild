#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

#define CACHE_TIMEOUT 600
#define MAX_CACHE_ENTRIES 10000
#define QUERY_QUEUE_SIZE 1000
#define MAX_CMDLINE_LEN 1024
#define MAX_FILEPATH_LEN 1024
#define SCAN_TIMEOUT 8  // 8秒扫描检测超时

#ifndef ATTR_REPL_IPV4_SRC
#define ATTR_REPL_IPV4_SRC ATTR_ORIG_IPV4_SRC
#define ATTR_REPL_IPV4_DST ATTR_ORIG_IPV4_DST  
#define ATTR_REPL_PORT_SRC ATTR_ORIG_PORT_SRC
#define ATTR_REPL_PORT_DST ATTR_ORIG_PORT_DST
#endif

// 系统兼容性检测
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
/* CentOS 7+ 和其他新系统 - 启用完整功能 */
#define ENABLE_PID_TRACKING 1
#else
/* SUSE 11 SP2 等旧系统 - 禁用 PID 追踪 */
#define ENABLE_PID_TRACKING 0
#endif

#if ENABLE_PID_TRACKING
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#endif

// 蜜罐端口列表
static uint16_t honeypot_ports[] = {
    21,    // FTP
    22,    // SSH
    23,    // Telnet  
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    443,   // HTTPS
    110,   // POP3
    143,   // IMAP
    993,   // IMAPS
    995,   // POP3S
    3389,  // RDP
    5900,  // VNC
    8080,  // HTTP-alt
    8443,  // HTTPS-alt
    135,   // MSRPC
    139,   // NetBIOS
    445,   // SMB
    1433,  // MSSQL
    3306,  // MySQL
    5432,  // PostgreSQL
    6379,  // Redis
    27017  // MongoDB
};
static int honeypot_port_count = sizeof(honeypot_ports) / sizeof(honeypot_ports[0]);

// 连接信息结构
typedef struct conn_info {
    uint8_t proto;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t direction; // 0=OUTBOUND, 1=INBOUND
    enum nf_conntrack_msg_type event_type;
    uint8_t tcp_state; // TCP状态
    time_t timestamp;
    struct conn_info *next;
} conn_info_t;

// 去重缓存条目
typedef struct dedup_cache {
    char key[256];
    time_t last_seen;
    struct dedup_cache *next;
} dedup_cache_t;

// PID缓存条目
typedef struct pid_cache {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t direction;
    pid_t pid;
    char proc_name[32];
    char cmdline[MAX_CMDLINE_LEN];
    char filepath[MAX_FILEPATH_LEN];
    time_t last_seen;
    struct pid_cache *next;
} pid_cache_t;

// 扫描检测结构
typedef struct scan_info {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t direction; // 0=OUTBOUND(主动扫描), 1=INBOUND(被扫描)
    time_t first_seen;
    time_t last_seen;
    uint16_t ports[1024];
    int port_count;
    struct scan_info *next;
} scan_info_t;

typedef struct listen_cache {
    uint32_t ip;
    uint16_t port;
    pid_t pid;
    char proc_name[32];
    char cmdline[MAX_CMDLINE_LEN];
    char filepath[MAX_FILEPATH_LEN];
    time_t last_seen;
    struct listen_cache *next;
} listen_cache_t;

static listen_cache_t *listen_cache_head = NULL;

// 全局变量
static pid_cache_t *pid_cache_head = NULL;
static int pid_cache_size = 0;

static dedup_cache_t *dedup_cache_head = NULL;
static int dedup_cache_size = 0;

static scan_info_t *scan_cache_head = NULL;
static int scan_cache_size = 0;

static conn_info_t *query_queue = NULL;
static conn_info_t *query_queue_tail = NULL;
static int queue_size = 0;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static int shutdown_flag = 0;
static uint32_t local_ips[10];
static int local_ip_count = 0;


// 获取本机所有IPv4地址
static void get_local_ips() {
    struct ifaddrs *ifaddr, *ifa;
    int i;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }
    
    for (ifa = ifaddr; ifa != NULL && local_ip_count < 10; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            
            if (sa->sin_addr.s_addr == htonl(INADDR_LOOPBACK) || 
                sa->sin_addr.s_addr == htonl(INADDR_ANY)) {
                continue;
            }
            
            local_ips[local_ip_count] = sa->sin_addr.s_addr;
            
            struct in_addr addr;
            addr.s_addr = sa->sin_addr.s_addr;
            printf("Local IPv4: %s\n", inet_ntoa(addr));
            
            local_ip_count++;
        }
    }
    
    freeifaddrs(ifaddr);
}

// 检查IP是否为本机IP
static int is_local_ip(uint32_t ip) {
    int i;
    for (i = 0; i < local_ip_count; i++) {
        if (ip == local_ips[i]) {
            return 1;
        }
    }
    return 0;
}

// 检查端口是否为蜜罐端口
static int is_honeypot_port(uint16_t port) {
    int i;
    for (i = 0; i < honeypot_port_count; i++) {
        if (port == honeypot_ports[i]) {
            return 1;
        }
    }
    return 0;
}

static void format_time(time_t timestamp, char *buf, size_t buf_size) {
    struct tm *tm_info = localtime(&timestamp);
    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// 根据进程PID获取进程名
static int get_process_name(pid_t pid, char *buf, size_t buf_size) {
    char path[64];
    FILE *fp;
    
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    
    if (fgets(buf, buf_size, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    
    fclose(fp);
    
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') {
        buf[len-1] = '\0';
    }
    
    return 0;
}

// 根据进程PID获取可执行文件路径
static int get_process_filepath(pid_t pid, char *buf, size_t buf_size) {
    char path[64];
    ssize_t len;
    
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    len = readlink(path, buf, buf_size - 1);
    if (len < 0) {
        return -1;
    }
    
    buf[len] = '\0';
    return 0;
}

// 根据进程PID获取命令行
static int get_process_cmdline(pid_t pid, char *buf, size_t buf_size) {
    char path[64];
    FILE *fp;
    
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    
    memset(buf, 0, buf_size);
    
    ssize_t bytes_read = fread(buf, 1, buf_size - 1, fp);
    fclose(fp);
    
    if (bytes_read <= 0) {
        return -1;
    }
    
    for (ssize_t i = 0; i < bytes_read; i++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    
    buf[bytes_read] = '\0';
    
    char *end = buf + strlen(buf) - 1;
    while (end > buf && *end == ' ') {
        *end-- = '\0';
    }
    
    return 0;
}

// 从INBOUND ESTABLISHED连接学习监听端口
static void learn_listen_port_from_established(conn_info_t *conn, pid_t pid, 
                                              const char *proc_name, const char *cmdline,
                                              const char *filepath) {
    if (conn->direction == 1 && conn->tcp_state == TCP_CONNTRACK_ESTABLISHED) {
        // 检查是否已经存在于缓存中
        listen_cache_t *current = listen_cache_head;
        while (current != NULL) {
            if (current->ip == conn->dst_ip && current->port == conn->dst_port) {
                // 更新现有记录
                current->pid = pid;
                strncpy(current->proc_name, proc_name, 31);
                strncpy(current->cmdline, cmdline, MAX_CMDLINE_LEN-1);
                strncpy(current->filepath, filepath, MAX_FILEPATH_LEN-1);
                current->last_seen = time(NULL);
                return;
            }
            current = current->next;
        }
        
        // 创建新记录
        listen_cache_t *new_entry = malloc(sizeof(listen_cache_t));
        if (new_entry == NULL) return;
        
        new_entry->ip = conn->dst_ip;
        new_entry->port = conn->dst_port;
        new_entry->pid = pid;
        strncpy(new_entry->proc_name, proc_name, 31);
        strncpy(new_entry->cmdline, cmdline, MAX_CMDLINE_LEN-1);
        strncpy(new_entry->filepath, filepath, MAX_FILEPATH_LEN-1);
        new_entry->last_seen = time(NULL);
        new_entry->next = listen_cache_head;
        listen_cache_head = new_entry;
        
        // 输出LISTEN日志
        char ip_str[INET_ADDRSTRLEN], time_str[64];
        struct in_addr addr;
        
        addr.s_addr = conn->dst_ip;
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        format_time(conn->timestamp, time_str, sizeof(time_str));
        
        printf("cat=New_Connection proto=tcp deviceDirection=IN src=0.0.0.0 dst=%s dport=%d spid=%d sproc=%s filePath=%s scmd=%s cs1=LISTEN start=%s\n",
               ip_str, conn->dst_port, pid, proc_name, filepath, cmdline, time_str);
        fflush(stdout);
    }
}

static void remove_from_scan_cache(uint32_t src_ip, uint32_t dst_ip, 
                                  uint16_t src_port, uint16_t dst_port, 
                                  uint8_t direction) {
    scan_info_t *current = scan_cache_head;
    scan_info_t *prev = NULL;
    
    while (current != NULL) {
        if (current->src_ip == src_ip && 
            current->dst_ip == dst_ip &&
            current->direction == direction) {
            
            // 从端口列表中删除特定的端口
            for (int i = 0; i < current->port_count; i++) {
                if (current->ports[i] == dst_port) {
                    // 移动数组元素来删除这个端口
                    for (int j = i; j < current->port_count - 1; j++) {
                        current->ports[j] = current->ports[j + 1];
                    }
                    current->port_count--;
                    break;
                }
            }
            
            // 如果这个扫描记录没有端口了，就删除整个记录
            if (current->port_count == 0) {
                scan_info_t *to_free = current;
                if (prev == NULL) {
                    scan_cache_head = current->next;
                } else {
                    prev->next = current->next;
                }
                current = current->next;
                free(to_free);
                scan_cache_size--;
            } else {
                prev = current;
                current = current->next;
            }
        } else {
            prev = current;
            current = current->next;
        }
    }
}

#if ENABLE_PID_TRACKING
// 通过inet_diag查询连接对应的PID - 仅CentOS 7+
static int query_pid_by_inet_diag(uint8_t proto, uint32_t src_ip, uint16_t src_port, 
                                 uint32_t dst_ip, uint16_t dst_port, pid_t *pid) {
    int fd, ret;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char buf[8192];
    
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_INET_DIAG);
    if (fd < 0) {
        return -1;
    }
    
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    
    if (bind(fd, (struct sockaddr*)&nladdr, sizeof(nladdr)) < 0) {
        close(fd);
        return -1;
    }
    
    struct inet_diag_req_v2 req;
    memset(&req, 0, sizeof(req));
    
    req.sdiag_family = AF_INET;
    req.sdiag_protocol = (proto == IPPROTO_TCP) ? IPPROTO_TCP : IPPROTO_UDP;
    req.idiag_ext = 0;
    req.idiag_states = -1;
    
    req.id.idiag_sport = htons(src_port);
    req.id.idiag_dport = htons(dst_port);
    req.id.idiag_src[0] = src_ip;
    req.id.idiag_dst[0] = dst_ip;
    
    struct nlmsghdr nlh;
    memset(&nlh, 0, sizeof(nlh));
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req));
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh.nlmsg_seq = time(NULL);
    
    struct iovec iov_send[2];
    iov_send[0].iov_base = &nlh;
    iov_send[0].iov_len = sizeof(nlh);
    iov_send[1].iov_base = &req;
    iov_send[1].iov_len = sizeof(req);
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = iov_send;
    msg.msg_iovlen = 2;
    
    ret = sendmsg(fd, &msg, 0);
    if (ret < 0) {
        close(fd);
        return -1;
    }
    
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    
    ret = recvmsg(fd, &msg, 0);
    if (ret < 0) {
        close(fd);
        return -1;
    }
    
    close(fd);
    
    struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
    if (!NLMSG_OK(hdr, ret) || hdr->nlmsg_type == NLMSG_ERROR) {
        return -1;
    }
    
    struct inet_diag_msg *diag = NLMSG_DATA(hdr);
    if (diag->idiag_family == AF_INET) {
        *pid = diag->idiag_inode;
        return 0;
    }
    
    return -1;
}

// 通过/proc查找inode对应的PID - 仅CentOS 7+
static pid_t find_pid_by_inode(uint32_t inode) {
    DIR *proc_dir, *fd_dir;
    struct dirent *proc_entry, *fd_entry;
    char fd_path[512], link_path[512], link_buf[512];
    pid_t pid = -1;
    
    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        return -1;
    }
    
    while ((proc_entry = readdir(proc_dir)) != NULL) {
        // 检查是否为数字目录（进程目录）
        char *endptr;
        pid_t current_pid = strtol(proc_entry->d_name, &endptr, 10);
        if (*endptr != '\0') continue;
        
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", current_pid);
        fd_dir = opendir(fd_path);
        if (fd_dir == NULL) continue;
        
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            // 跳过.和..目录
            if (strcmp(fd_entry->d_name, ".") == 0 || strcmp(fd_entry->d_name, "..") == 0)
                continue;
            
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path, link_buf, sizeof(link_buf)-1);
            if (len < 0) continue;
            
            link_buf[len] = '\0';
            
            if (strncmp(link_buf, "socket:[", 8) == 0) {
                uint32_t fd_inode;
                if (sscanf(link_buf + 8, "%u]", &fd_inode) == 1) {
                    if (fd_inode == inode) {
                        pid = current_pid;
                        break;
                    }
                }
            }
        }
        
        closedir(fd_dir);
        if (pid != -1) break;
    }
    
    closedir(proc_dir);
    return pid;
}
#endif

// 查询PID缓存
static int get_cached_pid(uint8_t proto, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port, uint8_t direction, 
                         pid_t *pid, char *proc_name, char *cmdline, char *filepath) {
    time_t now = time(NULL);
    pid_cache_t *current = pid_cache_head;
    pid_cache_t *prev = NULL;
    
    while (current != NULL) {
        if (now - current->last_seen > CACHE_TIMEOUT) {
            pid_cache_t *to_free = current;
            if (prev == NULL) {
                pid_cache_head = current->next;
            } else {
                prev->next = current->next;
            }
            current = current->next;
            free(to_free);
            pid_cache_size--;
            continue;
        }
        
        if (current->proto == proto &&
            current->src_ip == src_ip &&
            current->dst_ip == dst_ip &&
            current->src_port == src_port &&
            current->dst_port == dst_port &&
            current->direction == direction) {
            
            *pid = current->pid;
            strncpy(proc_name, current->proc_name, 31);
            strncpy(cmdline, current->cmdline, MAX_CMDLINE_LEN-1);
            strncpy(filepath, current->filepath, MAX_FILEPATH_LEN-1);
            current->last_seen = now;
            return 0;
        }
        
        prev = current;
        current = current->next;
    }
    
    return -1;
}

// 添加PID缓存
static void add_pid_cache(uint8_t proto, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port, uint8_t direction, 
                         pid_t pid, const char *proc_name, const char *cmdline, const char *filepath) {
    time_t now = time(NULL);
    
    if (pid_cache_size >= MAX_CACHE_ENTRIES) {
        pid_cache_t *current = pid_cache_head;
        pid_cache_t *prev = NULL;
        
        while (current != NULL) {
            if (now - current->last_seen > CACHE_TIMEOUT) {
                pid_cache_t *to_free = current;
                if (prev == NULL) {
                    pid_cache_head = current->next;
                } else {
                    prev->next = current->next;
                }
                current = current->next;
                free(to_free);
                pid_cache_size--;
            } else {
                prev = current;
                current = current->next;
            }
        }
    }
    
    pid_cache_t *new_entry = malloc(sizeof(pid_cache_t));
    if (new_entry == NULL) return;
    
    new_entry->proto = proto;
    new_entry->src_ip = src_ip;
    new_entry->dst_ip = dst_ip;
    new_entry->src_port = src_port;
    new_entry->dst_port = dst_port;
    new_entry->direction = direction;
    new_entry->pid = pid;
    strncpy(new_entry->proc_name, proc_name, 31);
    strncpy(new_entry->cmdline, cmdline, MAX_CMDLINE_LEN-1);
    strncpy(new_entry->filepath, filepath, MAX_FILEPATH_LEN-1);
    new_entry->last_seen = now;
    new_entry->next = pid_cache_head;
    pid_cache_head = new_entry;
    pid_cache_size++;
}

// 查询连接对应的PID和进程信息
static int query_connection_pid(uint8_t proto, uint32_t src_ip, uint16_t src_port,
                               uint32_t dst_ip, uint16_t dst_port, uint8_t direction,
                               pid_t *pid, char *proc_name, char *cmdline, char *filepath) {
    
#if ENABLE_PID_TRACKING
    // CentOS 7+: 完整的 PID 查询逻辑
    // 先查缓存
    if (get_cached_pid(proto, src_ip, dst_ip, src_port, dst_port, direction, 
                      pid, proc_name, cmdline, filepath) == 0) {
        return 0;
    }
    
    uint32_t inode = 0;
    
    if (direction == 1) { // INBOUND
        if (query_pid_by_inet_diag(proto, dst_ip, dst_port, 0, 0, (pid_t*)&inode) == 0 ||
            query_pid_by_inet_diag(proto, dst_ip, dst_port, src_ip, src_port, (pid_t*)&inode) == 0) {
            // 成功获取 inode
        }
    } else { // OUTBOUND
        query_pid_by_inet_diag(proto, src_ip, src_port, dst_ip, dst_port, (pid_t*)&inode);
    }
    
    if (inode != 0) {
        *pid = find_pid_by_inode(inode);
        if (*pid != -1) {
            if (get_process_name(*pid, proc_name, 32) == 0) {
                get_process_cmdline(*pid, cmdline, MAX_CMDLINE_LEN);
                get_process_filepath(*pid, filepath, MAX_FILEPATH_LEN);
                add_pid_cache(proto, src_ip, dst_ip, src_port, dst_port, direction, 
                             *pid, proc_name, cmdline, filepath);
                return 0;
            }
        }
    }
    
    // 查询失败，返回默认值
    *pid = -1;
    strcpy(proc_name, "unknown");
    strcpy(cmdline, "unknown");
    strcpy(filepath, "unknown");
    return -1;
    
#else
    // SUSE 11 SP2: 直接返回 unknown
    *pid = -1;
    strcpy(proc_name, "unknown");
    strcpy(cmdline, "unknown");
    strcpy(filepath, "unknown");
    return -1;
#endif
}

// 检查去重缓存 - 所有情况都基于目标IP和端口去重
static int is_duplicate(uint8_t proto, uint8_t direction, uint32_t src_ip, 
                       uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, pid_t pid) {
    time_t now = time(NULL);
    dedup_cache_t *current = dedup_cache_head;
    dedup_cache_t *prev = NULL;
    
    char key[64];
    
    // 简化：所有连接都基于目标IP和端口去重（源端口都是随机的）
    if (proto == IPPROTO_TCP && pid != -1) {
        // TCP ESTABLISHED: 包含PID信息
        snprintf(key, sizeof(key), "tcp_%d_%u_%d_%d", 
                 direction, dst_ip, dst_port, pid);
    } else {
        // UDP和其他TCP状态: 基于目标IP和端口
        snprintf(key, sizeof(key), "%s_%d_%u_%d", 
                 (proto == IPPROTO_TCP) ? "tcp" : "udp", 
                 direction, dst_ip, dst_port);
    }
    
    while (current != NULL) {
        if (now - current->last_seen > CACHE_TIMEOUT) {
            dedup_cache_t *to_free = current;
            if (prev == NULL) {
                dedup_cache_head = current->next;
            } else {
                prev->next = current->next;
            }
            current = current->next;
            free(to_free);
            dedup_cache_size--;
            continue;
        }
        
        if (strcmp(current->key, key) == 0) {
            current->last_seen = now;
            return 1; // 是重复的
        }
        
        prev = current;
        current = current->next;
    }
    
    dedup_cache_t *new_entry = malloc(sizeof(dedup_cache_t));
    if (new_entry == NULL) return 0;
    
    strncpy(new_entry->key, key, sizeof(new_entry->key)-1);
    new_entry->last_seen = now;
    new_entry->next = dedup_cache_head;
    dedup_cache_head = new_entry;
    dedup_cache_size++;
    
    return 0; // 不是重复的
}

// 处理SYN扫描检测
static void process_syn_scan(conn_info_t *conn) {
    time_t now = time(NULL);
    scan_info_t *current = scan_cache_head;
    scan_info_t *prev = NULL;
    
    scan_info_t *found = NULL;
    
    while (current != NULL) {
        if (current->src_ip == conn->src_ip && 
            current->dst_ip == conn->dst_ip &&
            current->direction == conn->direction) {
            found = current;
            break;
        }
        current = current->next;
    }
    
    if (found == NULL) {
        // 创建新的扫描记录
        found = malloc(sizeof(scan_info_t));
        if (found == NULL) return;
        
        found->src_ip = conn->src_ip;
        found->dst_ip = conn->dst_ip;
        found->direction = conn->direction;
        found->first_seen = now;
        found->last_seen = now;
        found->port_count = 0;
        memset(found->ports, 0, sizeof(found->ports));
        
        found->next = scan_cache_head;
        scan_cache_head = found;
        scan_cache_size++;
    } else {
        found->last_seen = now;
    }
    
    // 更新端口统计（去重）
    int port_exists = 0;
    for (int i = 0; i < found->port_count; i++) {
        if (found->ports[i] == conn->dst_port) {
            port_exists = 1;
            break;
        }
    }
    
    if (!port_exists && found->port_count < 1024) {
        found->ports[found->port_count++] = conn->dst_port;
    }
}

// 清理过期扫描记录并生成检测日志
static void cleanup_expired_scans() {
    time_t now = time(NULL);
    scan_info_t *current = scan_cache_head;
    scan_info_t *prev = NULL;
    
    while (current != NULL) {
        // 检查是否超时（8秒）且未转换为ESTABLISHED
        if (now - current->last_seen > SCAN_TIMEOUT && current->port_count > 0) {
            
            // 统计蜜罐端口的数量
            int honeypot_count = 0;
            for (int i = 0; i < current->port_count; i++) {
                if (is_honeypot_port(current->ports[i])) {
                    honeypot_count++;
                }
            }
            
            // 如果扫描的蜜罐端口数量达到阈值（比如3个），就报警
            if (honeypot_count >= 3) {
                // 生成扫描检测日志
                char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
                struct in_addr addr;
                char time_str[64];
                
                addr.s_addr = current->src_ip;
                inet_ntop(AF_INET, &addr, src_str, sizeof(src_str));
                
                addr.s_addr = current->dst_ip;
                inet_ntop(AF_INET, &addr, dst_str, sizeof(dst_str));
                
                format_time(current->last_seen, time_str, sizeof(time_str));
                
                // 构建端口列表字符串
                char port_list[256] = "";
                int written = 0;
                for (int i = 0; i < current->port_count && written < 250; i++) {
                    if (is_honeypot_port(current->ports[i])) {
                        int len = snprintf(port_list + written, sizeof(port_list) - written, 
                                         "%d,", current->ports[i]);
                        if (len > 0) written += len;
                    }
                }
                // 去掉最后一个逗号
                if (written > 0) port_list[written-1] = '\0';
                
                if (current->direction == 0) {
                    // 主动扫描 (OUTBOUND)
                    printf("cat=Port_Scan proto=tcp deviceDirection=OUT src=%s dst=%s cs1=SYN_SEND_Scanner cn1=%d cs2=Honeypot_Ports cs3=%s start=%s\n",
                           src_str, dst_str, honeypot_count, port_list, time_str);
                } else {
                    // 被扫描 (INBOUND)  
                    printf("cat=Port_Scan proto=tcp deviceDirection=IN src=%s dst=%s cs1=SYN_RECV_Scanner cn1=%d cs2=Honeypot_Ports cs3=%s start=%s\n",
                           src_str, dst_str, honeypot_count, port_list, time_str);
                }
                
                fflush(stdout);
                
                // 移除已报告的扫描记录
                scan_info_t *to_free = current;
                if (prev == NULL) {
                    scan_cache_head = current->next;
                } else {
                    prev->next = current->next;
                }
                current = current->next;
                free(to_free);
                scan_cache_size--;
                continue;
            } else if (current->port_count >= 10) {
                // 即使不是蜜罐端口，但扫描了大量端口也要报警
                char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
                struct in_addr addr;
                char time_str[64];
                
                addr.s_addr = current->src_ip;
                inet_ntop(AF_INET, &addr, src_str, sizeof(src_str));
                
                addr.s_addr = current->dst_ip;
                inet_ntop(AF_INET, &addr, dst_str, sizeof(dst_str));
                
                format_time(current->last_seen, time_str, sizeof(time_str));
                
                if (current->direction == 0) {
                    printf("cat=Port_Scan proto=tcp deviceDirection=OUT src=%s dst=%s cs1=SYN_SEND_Scanner cn1=%d cs2=Mass_Port_Scan start=%s\n",
                           src_str, dst_str, current->port_count, time_str);
                } else {
                    printf("cat=Port_Scan proto=tcp deviceDirection=IN src=%s dst=%s cs1=SYN_RECV_Scanner cn1=%d cs2=Mass_Port_Scan start=%s\n",
                           src_str, dst_str, current->port_count, time_str);
                }
                
                fflush(stdout);
                
                scan_info_t *to_free = current;
                if (prev == NULL) {
                    scan_cache_head = current->next;
                } else {
                    prev->next = current->next;
                }
                current = current->next;
                free(to_free);
                scan_cache_size--;
                continue;
            } else {
                // 端口数量太少，直接删除记录不打印
                scan_info_t *to_free = current;
                if (prev == NULL) {
                    scan_cache_head = current->next;
                } else {
                    prev->next = current->next;
                }
                current = current->next;
                free(to_free);
                scan_cache_size--;
                continue;
            }
        }
        
        prev = current;
        current = current->next;
    }
}

static void add_to_query_queue(uint8_t proto, uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port, uint8_t direction,
                              enum nf_conntrack_msg_type event_type, uint8_t tcp_state, time_t timestamp) {
    pthread_mutex_lock(&queue_mutex);
    
    if (queue_size >= QUERY_QUEUE_SIZE) {
        conn_info_t *oldest = query_queue;
        if (oldest != NULL) {
            query_queue = oldest->next;
            free(oldest);
            queue_size--;
            
            if (query_queue == NULL) {
                query_queue_tail = NULL;
            }
        }
    }
    
    conn_info_t *new_conn = malloc(sizeof(conn_info_t));
    if (new_conn == NULL) {
        pthread_mutex_unlock(&queue_mutex);
        return;
    }
    
    new_conn->proto = proto;
    new_conn->src_ip = src_ip;
    new_conn->dst_ip = dst_ip;
    new_conn->src_port = src_port;
    new_conn->dst_port = dst_port;
    new_conn->direction = direction;
    new_conn->event_type = event_type;
    new_conn->tcp_state = tcp_state;
    new_conn->timestamp = timestamp;
    new_conn->next = NULL;
    
    if (query_queue_tail == NULL) {
        query_queue = query_queue_tail = new_conn;
    } else {
        query_queue_tail->next = new_conn;
        query_queue_tail = new_conn;
    }
    queue_size++;
    
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

// 查询线程函数
static void* query_thread_func(void *arg) {
    while (1) {
        // 清理过期扫描记录并生成检测日志
        cleanup_expired_scans();
        
        pthread_mutex_lock(&queue_mutex);
        
        while (query_queue == NULL && !shutdown_flag) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        
        if (shutdown_flag && query_queue == NULL) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        
        conn_info_t *conn = query_queue;
        query_queue = conn->next;
        if (query_queue == NULL) {
            query_queue_tail = NULL;
        }
        queue_size--;
        
        pthread_mutex_unlock(&queue_mutex);
        
        // 如果连接变为ESTABLISHED，从扫描缓存中删除对应的记录
        if (conn->tcp_state == TCP_CONNTRACK_ESTABLISHED) {
            remove_from_scan_cache(conn->src_ip, conn->dst_ip, conn->src_port, conn->dst_port, conn->direction);
        }
        
        // 处理SYN_SEND和SYN_RECV状态的扫描检测
        if (conn->tcp_state == TCP_CONNTRACK_SYN_SENT || 
            conn->tcp_state == TCP_CONNTRACK_SYN_RECV) {
            process_syn_scan(conn);
        }
        
        // 查询PID信息（在CentOS 7上会获取真实PID，在SUSE 11 SP2上返回unknown）
        pid_t pid = -1;
        char proc_name[32] = "unknown";
        char cmdline[MAX_CMDLINE_LEN] = "unknown";
        char filepath[MAX_FILEPATH_LEN] = "unknown";
        
        if (conn->tcp_state == TCP_CONNTRACK_ESTABLISHED) {
            query_connection_pid(conn->proto, conn->src_ip, conn->src_port,
                               conn->dst_ip, conn->dst_port, conn->direction,
                               &pid, proc_name, cmdline, filepath);
            
            // 从INBOUND ESTABLISHED连接学习监听端口信息
            if (conn->direction == 1) { // INBOUND
                learn_listen_port_from_established(conn, pid, proc_name, cmdline, filepath);
            }
        }
        
        // 检查去重（TCP ESTABLISHED和所有UDP连接都需要去重）
        if ((conn->proto == IPPROTO_TCP && conn->tcp_state == TCP_CONNTRACK_ESTABLISHED) || 
            conn->proto == IPPROTO_UDP) {
            if (is_duplicate(conn->proto, conn->direction, conn->src_ip, 
                            conn->dst_ip, conn->src_port, conn->dst_port, pid)) {
                // 如果是重复的连接，跳过输出
                free(conn);
                continue;
            }
        }
        
        // 检查是否需要输出
        int should_output = 0;
        
        if (conn->proto == IPPROTO_UDP) {
            // UDP连接都输出
            should_output = 1;
        } else if (conn->proto == IPPROTO_TCP) {
            // TCP连接只输出ESTABLISHED状态
            if (conn->tcp_state == TCP_CONNTRACK_ESTABLISHED) {
                should_output = 1;
            }
            // SYN_SEND/SYN_RECV 在扫描检测中处理，这里不输出
        }
        
        if (should_output) {
            char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
            struct in_addr addr;
            
            addr.s_addr = conn->src_ip;
            inet_ntop(AF_INET, &addr, src_str, sizeof(src_str));
            
            addr.s_addr = conn->dst_ip;
            inet_ntop(AF_INET, &addr, dst_str, sizeof(dst_str));
            
            // 只保留第二种格式的输出
            char time_str[64];
            format_time(conn->timestamp, time_str, sizeof(time_str));
            
            const char *cat_str = "New_Connection";
            const char *detailed_proto = (conn->proto == IPPROTO_TCP) ? "tcp" : "udp";
            const char *device_direction = (conn->direction == 0) ? "OUT" : "IN";
            
            // 输出格式：不显示源端口（因为都是随机的）
            printf("cat=%s proto=%s deviceDirection=%s src=%s dst=%s dport=%d",
                   cat_str, detailed_proto, device_direction,
                   src_str, dst_str, conn->dst_port);
            
            if (conn->tcp_state == TCP_CONNTRACK_ESTABLISHED) {
                printf(" spid=%d sproc=%s filePath=%s scmd=%s cs1=ESTABLISHED start=%s\n",
                       pid, proc_name, filepath, cmdline, time_str);
            } else {
                printf(" start=%s\n", time_str);
            }
            
            fflush(stdout);
        }
        
        free(conn);
    }
    
    return NULL;
}

static int conntrack_callback(enum nf_conntrack_msg_type type,
                             struct nf_conntrack *ct,
                             void *data) {
    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    
    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) &&
        nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) == AF_INET) {
        
        uint16_t src_port, dst_port;
        uint32_t src_ip, dst_ip;
        
        // 对于ESTABLISHED状态，使用回复方向的端口信息来查询PID
        uint8_t tcp_state = 0;
        if (proto == IPPROTO_TCP) {
            tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
        }
        
        if (tcp_state == TCP_CONNTRACK_ESTABLISHED) {
            // ESTABLISHED状态：使用回复方向的信息（这样能拿到正确的源端口）
            struct in_addr *src = (struct in_addr*)nfct_get_attr(ct, ATTR_REPL_IPV4_SRC);
            struct in_addr *dst = (struct in_addr*)nfct_get_attr(ct, ATTR_REPL_IPV4_DST);
            src_ip = src->s_addr;
            dst_ip = dst->s_addr;
            src_port = ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
            dst_port = ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));
        } else {
            // 其他状态：使用原始方向的信息
            struct in_addr *src = (struct in_addr*)nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC);
            struct in_addr *dst = (struct in_addr*)nfct_get_attr(ct, ATTR_ORIG_IPV4_DST);
            src_ip = src->s_addr;
            dst_ip = dst->s_addr;
            src_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
            dst_port = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
        }
        
        // 检查源和目标都是本机IP，如果是则忽略
        if (is_local_ip(src_ip) && is_local_ip(dst_ip)) {
            return NFCT_CB_CONTINUE;
        }
        
        uint8_t direction;
        
        if (is_local_ip(src_ip)) {
            direction = 0; // OUTBOUND
        } else if (is_local_ip(dst_ip)) {
            direction = 1; // INBOUND
        } else {
            return NFCT_CB_CONTINUE;
        }
        
        add_to_query_queue(proto, src_ip, dst_ip, src_port, dst_port, direction, type, tcp_state, time(NULL));
    }
    
    return NFCT_CB_CONTINUE;
}

// 清理函数
static void cleanup() {
    shutdown_flag = 1;
    pthread_cond_broadcast(&queue_cond);
    
    pid_cache_t *current = pid_cache_head;
    while (current != NULL) {
        pid_cache_t *next = current->next;
        free(current);
        current = next;
    }
    pid_cache_head = NULL;
    
    dedup_cache_t *dedup_current = dedup_cache_head;
    while (dedup_current != NULL) {
        dedup_cache_t *dedup_next = dedup_current->next;
        free(dedup_current);
        dedup_current = dedup_next;
    }
    dedup_cache_head = NULL;
    
    scan_info_t *scan_current = scan_cache_head;
    while (scan_current != NULL) {
        scan_info_t *scan_next = scan_current->next;
        free(scan_current);
        scan_current = scan_next;
    }
    scan_cache_head = NULL;
    
    listen_cache_t *listen_current = listen_cache_head;
    while (listen_current != NULL) {
        listen_cache_t *listen_next = listen_current->next;
        free(listen_current);
        listen_current = listen_next;
    }
    listen_cache_head = NULL;
    
    conn_info_t *conn = query_queue;
    while (conn != NULL) {
        conn_info_t *next = conn->next;
        free(conn);
        conn = next;
    }
    query_queue = NULL;
    query_queue_tail = NULL;
}

int main() {
    pthread_t query_thread;
    
    printf("Starting conntrack monitor...\n");
#if ENABLE_PID_TRACKING
    printf("System: CentOS 7+ (PID tracking enabled)\n");
#else
    printf("System: SUSE 11 SP2 (PID tracking disabled)\n");
#endif
    printf("Format: cat=New_Connection proto=proto deviceDirection=DIR src=SRC dst=DST dport=DPORT spid=PID sproc=PROC filePath=PATH scmd=CMD cs1=STATE start=TIME\n");
    printf("Scan Detection: SYN_SEND/SYN_RECV Scanner detection enabled\n\n");
    
    get_local_ips();
    printf("Found %d local IPv4 addresses\n", local_ip_count);
    printf("Monitoring %d honeypot ports\n\n", honeypot_port_count);
    
    if (local_ip_count == 0) {
        printf("Warning: No local IPv4 addresses found!\n");
    }
    
    atexit(cleanup);
    
    if (pthread_create(&query_thread, NULL, query_thread_func, NULL) != 0) {
        perror("pthread_create failed");
        return 1;
    }
    
    struct nfct_handle *h = nfct_open(CONNTRACK, 
        NF_NETLINK_CONNTRACK_NEW | 
        NF_NETLINK_CONNTRACK_UPDATE | 
        NF_NETLINK_CONNTRACK_DESTROY);
    
    if (h == NULL) {
        perror("nfct_open failed");
        shutdown_flag = 1;
        pthread_join(query_thread, NULL);
        return 1;
    }
    
    if (nfct_callback_register(h, NFCT_T_ALL, conntrack_callback, NULL) < 0) {
        perror("nfct_callback_register failed");
        nfct_close(h);
        shutdown_flag = 1;
        pthread_join(query_thread, NULL);
        return 1;
    }
    
    printf("Monitoring started. Waiting for connection events...\n");
    
    int ret = nfct_catch(h);
    if (ret == -1) {
        perror("nfct_catch failed");
    }
    
    nfct_close(h);
    shutdown_flag = 1;
    pthread_cond_broadcast(&queue_cond);
    pthread_join(query_thread, NULL);
    
    return 0;
}
