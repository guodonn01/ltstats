/*
Copyright 2025 Lukas Tautz

This file is part of LTstats <https://ltstats.de>.

LTstats is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "server.h"

void sigchld_handler(void) {
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0)
        __atomic_sub_fetch(&children, 1, __ATOMIC_RELAXED);
}

void sigalrm_handler(void) {
    close(client);
    _exit(2);
}

bool sock_ready(int fd, bool read, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = read ? POLLIN : POLLOUT, .revents = 0 };
    if (poll(&pfd, 1, timeout_ms) > 0)
        return (pfd.revents & (read ? POLLIN : POLLOUT)) && !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL));
    return false;
}

monitor_details_t *get_monitor_details_by_public(const char token[32]) {
    for (uint32 i = 0; i < details_count; ++i)
        if (!memcmp(details[i].public_token, token, 32))
            return details + i;
    return NULL;
}

monitor_details_t *get_monitor_details_by_private(const char token[32]) {
    for (uint32 i = 0; i < details_count; ++i)
        if (!memcmp(details[i].token, token, 32))
            return details + i;
    return NULL;
}

notification_monitor_details_t *get_notification_monitor_details_by_private(const char token[32]) {
    for (uint32 i = 0; i < details_count; ++i)
        if (!memcmp(notification_details[i].token, token, 32))
            return notification_details + i;
    return NULL;
}

int open_with_retries(const char *filename, int flags) {
    uint8 tries = 0;
    int fd;
    do
        fd = open(filename, flags, S_IRUSR | S_IWUSR);
    while (fd == -1 && ++tries < 5);
    if (fd == -1) {
        write(2, SLEN("Error: can't open a file. Check permissions and RLIMIT_NOFILE.\n"));
        _exit(10);
    }
    return fd;
}

uint32 fd_size(int fd) {
    struct stat data;
    if (fstat(fd, &data) == -1)
        return false;
    return data.st_size;
}

json_object *load_json_file(char *name) {
    int fd;
    fd = open_with_retries(name, O_RDONLY);
    uint32 data_size = fd_size(fd);
    char *buf = malloc(data_size + 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    buf[data_size] = '\0';
    uint32 read_data = 0;
    int32 tmp;
    while ((data_size - read_data) && (tmp = read(fd, buf + read_data, data_size - read_data)) > 0)
        read_data += tmp;
    close(fd);
    json_tokener *tokener;
    if (read_data != data_size || !(tokener = json_tokener_new())) {
        free(buf);
        return NULL;
    }
    json_object *ret = json_tokener_parse_ex(tokener, buf, data_size + 1);
    json_tokener_free(tokener);
    free(buf);
    return ret;
}

void load_totals(monitor_details_t *monitor) { // http_buf is used even though this is no HTTP, but this isn't problematic
    monitor->rx_total = monitor->tx_total = monitor->sectors_read_total = monitor->sectors_written_total = 0;
    uint32 file_len = fd_size(monitor->fd), pos = 0;
    int32 read_len;
    if (!file_len) // problematic in case fstat failed, but not much else to do here...
        return;
    while (pos < file_len && (read_len = pread(monitor->fd, http_buf, min(sizeof(stats_t) * (sizeof(http_buf) / sizeof(stats_t)), file_len - pos), pos)) > 0) {
        uint16 count = read_len / sizeof(stats_t);
        pos += count * sizeof(stats_t);
        for (uint16 i = 0; i < count; ++i) {
            stats_t *element = (stats_t *)http_buf + i;
            monitor->rx_total += element->rx_bytes;
            monitor->tx_total += element->tx_bytes;
            monitor->sectors_read_total += element->read_sectors;
            monitor->sectors_written_total += element->written_sectors;
        }
    }
}

#define HIDE_KEY_CASE(_str, _key) \
    if (key_len == strlen(_str) && !memcmp(_str, key_str, strlen(_str))) { \
        should_hide[_key] = true; \
        continue; \
    } else

#define MONITORS_FOREACH \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"") \
    if (new_details) { \
        uint32 current_details_pos = 0; \
        json_object_object_foreach(monitors, key, val) {
            json_object *token;
            const char *token_str;

#define MONITORS_FOREACH_TOKEN_CHECK strlen(key) != 32 || !(token = json_object_array_get_idx(val, 0)) || !json_object_is_type(token, json_type_string) || json_object_get_string_len(token) != 32 || !(token_str = json_object_get_string(token))

#define MONITORS_FOREACH_END \
            ++current_details_pos; \
        } \
    } \
    _Pragma("GCC diagnostic pop")


// if parse_data_json() returns false, you MAY NOT access data_json, monitors, status_pages and admin_hash. details and close_fds should be safe to access in any case.
bool parse_data_json(void) {
    if (data_json)
        json_object_put(data_json);
    data_json = load_json_file("data.json");
    json_object *tmp_json;
    if (!data_json || !json_object_is_type(data_json, json_type_object) ||
        !json_object_object_get_ex(data_json, "monitors", &monitors) || !json_object_is_type(monitors, json_type_object))
        return false;
    uint32 new_details_count = json_object_object_length(monitors);
    if (proc == PROC_NOTIFICATIONS) {
        notification_monitor_details_t *new_details = NULL;
        if (new_details_count && !(new_details = malloc(new_details_count * sizeof(notification_monitor_details_t))))
            return false;
        MONITORS_FOREACH
                if (MONITORS_FOREACH_TOKEN_CHECK || !(new_details[current_details_pos].name = json_object_array_get_idx(val, 1)) || !(new_details[current_details_pos].monitoring_settings = json_object_array_get_idx(val, 4))) {
                    for (uint32 new_details_pos = 0; new_details_pos < current_details_pos; ++new_details_pos) // close fds of new monitors
                        if (!get_notification_monitor_details_by_private(new_details[new_details_pos].token)) {
                            close(new_details[new_details_pos].fd);
                            if (new_details[new_details_pos].latency_fd != -1) close(new_details[new_details_pos].latency_fd);
                        }
                    free(new_details);
                    return false;
                }
                memcpy(new_details[current_details_pos].token, token_str, 33); // also copy nullbyte
                memcpy(new_details[current_details_pos].public_token, key, 33); // also copy nullbyte
                notification_monitor_details_t *tmp_monitor;
                if ((tmp_monitor = get_notification_monitor_details_by_private(token_str))) {
                    new_details[current_details_pos].fd = tmp_monitor->fd;
                    new_details[current_details_pos].latency_fd = tmp_monitor->latency_fd;
                    memcpy(&new_details[current_details_pos].notification_sent, &tmp_monitor->notification_sent, sizeof(new_details[current_details_pos].notification_sent));
                } else {
                    new_details[current_details_pos].fd = open_with_retries(token_str, O_RDWR | O_CREAT | O_APPEND);
                    char latency_filename[64];
                    snprintf(latency_filename, sizeof(latency_filename), "%s_latency", token_str);
                    new_details[current_details_pos].latency_fd = open_with_retries(latency_filename, O_RDWR | O_CREAT | O_APPEND);
                    memset(&new_details[current_details_pos].notification_sent, 0, sizeof(new_details[current_details_pos].notification_sent));
                }
        MONITORS_FOREACH_END
        if (notification_details) {
            for (uint32 details_pos = 0; details_pos < details_count; ++details_pos)
                if (!json_object_object_get_ex(monitors, notification_details[details_pos].public_token, &tmp_json)) {
                    close(notification_details[details_pos].fd);
                    if (notification_details[details_pos].latency_fd != -1) close(notification_details[details_pos].latency_fd);
                }
            free(notification_details);
        }
        details_count = new_details_count;
        notification_details = new_details;
        return true;
    }
    if (!json_object_object_get_ex(data_json, "hash", &tmp_json) || !json_object_is_type(tmp_json, json_type_string) || json_object_get_string_len(tmp_json) != 64 || !(admin_hash = json_object_get_string(tmp_json)) ||
        !json_object_object_get_ex(data_json, "pages", &status_pages) || !json_object_is_type(status_pages, json_type_object) ||
        !json_object_object_get_ex(data_json, "hide", &tmp_json) || !json_object_is_type(tmp_json, json_type_array))
        return false;
    memset(should_hide, 0, sizeof(should_hide));
    uint8 len = json_object_array_length(tmp_json);
    for (uint8 i = 0; i < len; ++i) {
        json_object *key = json_object_array_get_idx(tmp_json, i);
        const char *key_str;
        uint8 key_len;
        if (!key || !json_object_is_type(key, json_type_string) || !(key_len = json_object_get_string_len(key)) || !(key_str = json_object_get_string(key)))
            return false;
        HIDE_KEY_CASE("TOTAL_IO", SHOULD_HIDE_TOTAL_IO)
        HIDE_KEY_CASE("TOTAL_TRAFFIC", SHOULD_HIDE_TOTAL_TRAFFIC)
        HIDE_KEY_CASE("KERNEL", SHOULD_HIDE_KERNEL)
        HIDE_KEY_CASE("CPU_MODEL", SHOULD_HIDE_CPU_MODEL)
        HIDE_KEY_CASE("CPU_CORES", SHOULD_HIDE_CPU_CORES)
        HIDE_KEY_CASE("UPTIME", SHOULD_HIDE_UPTIME)
        HIDE_KEY_CASE("CPU_USAGE", SHOULD_HIDE_CPU_USAGE)
        HIDE_KEY_CASE("CPU_IOWAIT", SHOULD_HIDE_CPU_IOWAIT)
        HIDE_KEY_CASE("CPU_STEAL", SHOULD_HIDE_CPU_STEAL)
        HIDE_KEY_CASE("RAM_SIZE", SHOULD_HIDE_RAM_SIZE)
        HIDE_KEY_CASE("RAM_USAGE", SHOULD_HIDE_RAM_USAGE)
        HIDE_KEY_CASE("SWAP_SIZE", SHOULD_HIDE_SWAP_SIZE)
        HIDE_KEY_CASE("SWAP_USAGE", SHOULD_HIDE_SWAP_USAGE)
        HIDE_KEY_CASE("DISK_SIZE", SHOULD_HIDE_DISK_SIZE)
        HIDE_KEY_CASE("DISK_USAGE", SHOULD_HIDE_DISK_USAGE)
        HIDE_KEY_CASE("NET", SHOULD_HIDE_NET)
        HIDE_KEY_CASE("IO", SHOULD_HIDE_IO)
        HIDE_KEY_CASE("LATENCY", SHOULD_HIDE_LATENCY)
        return false; // if none of the cases matches
    }
    monitor_details_t *new_details = NULL;
    if (new_details_count && !(new_details = malloc(new_details_count * sizeof(monitor_details_t))))
        return false;
    MONITORS_FOREACH
        json_object *is_public;
        if (MONITORS_FOREACH_TOKEN_CHECK || !(is_public = json_object_array_get_idx(val, 2)) || !json_object_is_type(is_public, json_type_boolean)) {
            for (uint32 new_details_pos = 0; new_details_pos < current_details_pos; ++new_details_pos) // close fds of new monitors
                if (!get_monitor_details_by_private(new_details[new_details_pos].token)) {
                    close(new_details[new_details_pos].fd);
                    if (new_details[new_details_pos].latency_fd != -1) close(new_details[new_details_pos].latency_fd);
                }
            free(new_details);
            return false;
        }
        memcpy(new_details[current_details_pos].token, token_str, 33); // also copy nullbyte
        memcpy(new_details[current_details_pos].public_token, key, 33); // also copy nullbyte
        new_details[current_details_pos].public = json_object_get_boolean(is_public);
        monitor_details_t *tmp_monitor;
        if ((tmp_monitor = get_monitor_details_by_private(token_str))) {
            new_details[current_details_pos].fd = tmp_monitor->fd;
            new_details[current_details_pos].latency_fd = tmp_monitor->latency_fd;
            new_details[current_details_pos].was_online = tmp_monitor->was_online;
            new_details[current_details_pos].rx_total = tmp_monitor->rx_total;
            new_details[current_details_pos].tx_total = tmp_monitor->tx_total;
            new_details[current_details_pos].sectors_read_total = tmp_monitor->sectors_read_total;
            new_details[current_details_pos].sectors_written_total = tmp_monitor->sectors_written_total;
            if (new_details[current_details_pos].was_online) {
                new_details[current_details_pos].time_diff = tmp_monitor->time_diff;
                memcpy(&new_details[current_details_pos].details, &tmp_monitor->details, sizeof(details_t));
                memcpy(&new_details[current_details_pos].stats, &tmp_monitor->stats, sizeof(stats_t));
            }
        } else {
            new_details[current_details_pos].was_online = false;
            new_details[current_details_pos].fd = open_with_retries(token_str, O_RDWR | O_CREAT | O_APPEND);
            char latency_filename[64];
            snprintf(latency_filename, sizeof(latency_filename), "%s_latency", token_str);
            new_details[current_details_pos].latency_fd = open_with_retries(latency_filename, O_RDWR | O_CREAT | O_APPEND);
            load_totals(&new_details[current_details_pos]);
        }
    MONITORS_FOREACH_END
    if (details) { // close_fds
        uint32 pos = close_fds_count, old_close_fds_count = close_fds_count;
        for (uint32 details_pos = 0; details_pos < details_count; ++details_pos)
            if (!json_object_object_get_ex(monitors, details[details_pos].public_token, &tmp_json)) {
                bool already_in_close_fds = false;
                for (uint32 close_fds_pos = 0; close_fds_pos < old_close_fds_count; ++close_fds_pos) // shouldn't (can't?) occur, but better check than double-closing it...
                    if (close_fds[close_fds_pos].fd == details[details_pos].fd) {
                        already_in_close_fds = true;
                        break;
                    }
                if (!already_in_close_fds)
                    ++close_fds_count;
            }
        if (close_fds_count > old_close_fds_count) {
            struct timespec monotonic_time;
            clock_gettime(CLOCK_MONOTONIC, &monotonic_time);
            if (close_fds) {
                void *realloced = realloc(close_fds, sizeof(close_fds_t) * close_fds_count);
                if (!realloced)
                    goto close_fds_alloc_err;
                close_fds = realloced;
            } else {
                close_fds = malloc(sizeof(close_fds_t) * close_fds_count);
                if (!close_fds) {
close_fds_alloc_err:
                    if (new_details) {
                        for (uint32 new_details_pos = 0; new_details_pos < new_details_count; ++new_details_pos) // close fds of new monitors
                            if (!get_monitor_details_by_private(new_details[new_details_pos].token)) {
                                close(new_details[new_details_pos].fd);
                                if (new_details[new_details_pos].latency_fd != -1) close(new_details[new_details_pos].latency_fd);
                            }
                        free(new_details);
                    }
                    close_fds_count = old_close_fds_count;
                    return false;
                }
            }
            for (uint32 details_pos = 0; details_pos < details_count; ++details_pos)
                if (!json_object_object_get_ex(monitors, details[details_pos].public_token, &tmp_json)) {
                    bool already_in_close_fds = false;
                    for (uint32 close_fds_pos = 0; close_fds_pos < old_close_fds_count; ++close_fds_pos) // shouldn't (can't?) occur, but better check than double-closing it...
                        if (close_fds[close_fds_pos].fd == details[details_pos].fd) {
                            already_in_close_fds = true;
                            break;
                        }
                    if (!already_in_close_fds) {
                        close_fds[pos].fd = details[details_pos].fd;
                        close_fds[pos].latency_fd = details[details_pos].latency_fd;
                        close_fds[pos].close_at = monotonic_time.tv_sec + 30;
                        unlink(details[details_pos].token);
                        char latency_filename[64];
                        snprintf(latency_filename, sizeof(latency_filename), "%s_latency", details[details_pos].token);
                        unlink(latency_filename);
                        ++pos;
                    }
                }
        }
    }
    details_count = new_details_count;
    if (details)
        free(details);
    details = new_details;
    return true;
}

void check_close_fds(void) {
    if (!close_fds)
        return;
    uint32 real_count = 0;
    struct timespec monotonic_time;
    clock_gettime(CLOCK_MONOTONIC, &monotonic_time);
    for (uint32 i = 0; i < close_fds_count; ++i) {
        if (close_fds[i].fd != -1) {
            if (close_fds[i].close_at <= monotonic_time.tv_sec) {
                close(close_fds[i].fd);
                close_fds[i].fd = -1;
                if (close_fds[i].latency_fd != -1) {
                    close(close_fds[i].latency_fd);
                    close_fds[i].latency_fd = -1;
                }
            } else
                ++real_count;
        }
    }
    if (!real_count) {
        free(close_fds);
        close_fds = NULL;
        close_fds_count = 0;
    }
}

#define client_write(s) client_write_len(SLEN(s))
bool client_write_len(const char *s, uint32 l) {
    uint32 pos = 0;
    int32 tmp;
    while (sock_ready(client, false, 5) && (tmp = write(client, s + pos, l - pos)) > 0 && (pos += tmp) < l);
    return pos == l;
}

bool client_sendfile(int fd, uint32 len) {
    off_t pos = 0;
    while (sock_ready(client, false, 5) && sendfile(client, fd, (off_t *)&pos, len - pos) > 0 && pos < len);
    return pos == len;
}

void client_http_sendfile(int fd) {
    uint16 len = 0;
    uint32 file_size = fd_size(fd);
    str_append(http_buf, &len, "HTTP/1.1 200\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: close\r\nContent-Length: ");
    str_append_uint(http_buf, &len, file_size);
    str_append(http_buf, &len, "\r\n\r\n");
    if (!client_write_len(http_buf, len))
        return;
    client_sendfile(fd, file_size);
}

void client_write_json(json_object *json) {
    size_t json_len;
    const char *json_str = json_object_to_json_string_length(json, JSON_C_TO_STRING_PLAIN, &json_len);
    uint16 len = 0;
    str_append(http_buf, &len, "HTTP/1.1 200\r\nContent-Type: application/json\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: ");
    str_append_uint(http_buf, &len, json_len);
    str_append(http_buf, &len, "\r\n\r\n");
    if (json_len + len > sizeof(http_buf)) {
        if (!client_write_len(http_buf, len))
            return;
        client_write_len(json_str, json_len);
    } else {
        // memcpy is cheaper than a syscall
        str_append_len(http_buf, &len, json_str, json_len);
        client_write_len(http_buf, len);
    }
    
}

uint16 get_http_body(void) {
    for (uint16 pos = strlen("GET / HTTP/1.1\r\n"); pos < len; ++pos)
        if (http_buf[pos] == '\n' && http_buf[pos - 2] == '\n' && http_buf[pos - 1] == '\r' && http_buf[pos - 3] == '\r')
            return pos + 1;
    return 0;
}

bool is_logged_in(void) {    
    bool searching_colon = false;
    for (uint16 http_buf_pos = strlen("GET / HTTP/1.1\r\n"); http_buf_pos < len; ++http_buf_pos) {
        if (searching_colon) {
            if (http_buf[http_buf_pos] == '\n') // invalid HTTP
                return false;
            if (http_buf[http_buf_pos] == ':') {
                if ((uint32)len < http_buf_pos + 64 + strlen("hash=\r\n\r\n"))
                    return false;
                ++http_buf_pos;
                if (http_buf[http_buf_pos] == ' ')
                    ++http_buf_pos;
                return !memcmp(http_buf + http_buf_pos, SLEN("hash=")) && !memcmp(http_buf + http_buf_pos + strlen("hash="), admin_hash, 64);
            }
        } else if (http_buf[http_buf_pos - 3] == '\n' && tolower(http_buf[http_buf_pos - 2]) == 'c' && tolower(http_buf[http_buf_pos - 1]) == 'o' && tolower(http_buf[http_buf_pos]) == 'o') // \ncoo, must be cookie:
            searching_colon = true;
    }
    return false;
}

#include "web.c"

/*
JSON format of data.json (PUBLIC_TOKEN and private_token should be unique and random (both 32 character hex strings)), arrays do not have keys (they're only here to explain their purpose):
 time: int, time the file was last changed
 hash: string, sha256 hash
 monitors: object
    {PUBLIC_TOKEN}: array
        - private_token: string
        - name: string
        - public: boolean
        - notes: false or array
            - text: string
            - public: boolean
        - monitoring: false or array
            - offline: false or int (minutes offline)
            - cpu_usage: false or int
            - cpu_iowait: false or int
            - cpu_steal: false or int
            - ram_usage: false or int
            - swap_usage: false or int
            - disk_usage: false or int
            - net_rx_bps: false or int (bps is bits per second)
            - net_tx_bps: false or int (bps is bits per second)
            - disk_read_bps: false or int (bps is bytes per second)
            - disk_write_tx_bps: false or int (bps is bytes per second)
        - additional_paths: array of strings, additional mounted paths to be monitored (/ will always be monitored). Specifying paths that result in one partition/filesystem to be monitored more than once may result in disk usage/totals/IO to be incorrect.
        - latency_monitors: array of objects (optional)
            - id: int
            - type: string ("icmp" or "tcp")
            - port: int (only used if type is "tcp", othe
        pages: object
    {PATH}: array
        - name: string
        - public: boolean
        - monitors: array of {PUBLIC_TOKEN}s
 hide: array of enum:
    - TOTAL_IO
    - TOTAL_TRAFFIC
    - KERNEL
    - CPU_MODEL
    - CPU_CORES
    - UPTIME
    - CPU_USAGE
    - CPU_IOWAIT
    - CPU_STEAL
    - RAM_SIZE
    - RAM_USAGE
    - SWAP_SIZE
    - SWAP_USAGE
    - DISK_SIZE
    - DISK_USAGE
    - NET
    - IO
  notifications: object
    every: int (seconds)
    exec: array of command line parameters, with the following possibly special arguments: NAME, TYPE, PUBLIC_TOKEN, STILL_MET, were TYPE is either {DOWN, CPU_USAGE, CPU_IOWAIT, CPU_STEAL, RAM_USAGE, SWAP_USAGE, DISK_USAGE, NET_RX, NET_TX, DISK_READ, DISK_WRITE} and STILL_MET is either {TRUE, FALSE}
    sample: int (how many minutes should be taken into account for the thresholds)
  copy: string, TOKEN will be replaced with the actual token
*/

extern char **environ;
void notify(json_object *exec, json_object *name, char *public_token, char *type, bool still_met) {
    if (!fork()) {
        uint16 len = json_object_array_length(exec);
        char *args[len + 1];
        args[len] = NULL;
        for (uint16 i = 0; i < len; ++i) {
            json_object *element = json_object_array_get_idx(exec, i);
            uint16 len = 0;
            const char *str;
            char *arg = NULL;
            if (!element || !json_object_is_type(element, json_type_string) || !(len = json_object_get_string_len(element)) || !(str = json_object_get_string(element)))
                _exit(0);
            if (len == strlen("NAME") && !memcmp(str, SLEN("NAME"))) {
                str = json_object_get_string(name);
                if (!str)
                    _exit(0);
            } else if (len == strlen("TYPE") && !memcmp(str, SLEN("TYPE")))
                arg = type;
            else if (len == strlen("PUBLIC_TOKEN") && !memcmp(str, SLEN("PUBLIC_TOKEN")))
                arg = public_token;
            else if (len == strlen("STILL_MET") && !memcmp(str, SLEN("STILL_MET")))
                arg = still_met ? "TRUE" : "FALSE";
            if (!arg) {
                arg = strdup(str); // because const shouldn't be casted away
                if (!arg)
                    _exit(0);
            }
            args[i] = arg;
        }
        execve(*args, args, environ);
        _exit(0);
    }
}

void notifications_proc(void) {
    proc = PROC_NOTIFICATIONS;
    uint32 last_id = 0;
start:
    while (!parse_data_json())
        usleep(500);
    json_object *notifications, *every, *exec, *sample;
    uint64 check_every, sample_count;
    if (!json_object_object_get_ex(data_json, "notifications", &notifications) || !json_object_is_type(notifications, json_type_object) ||
        !json_object_object_get_ex(notifications, "every", &every) || !json_object_is_type(every, json_type_int) ||
        !json_object_object_get_ex(notifications, "exec", &exec) || !json_object_is_type(exec, json_type_array) ||
        !json_object_object_get_ex(notifications, "sample", &sample) || !json_object_is_type(sample, json_type_int) ||
        !(check_every = json_object_get_uint64(every)) ||
        !(sample_count = json_object_get_uint64(sample))) {
        usleep(500);
        goto start;
    }
    for (;;) {
        uint32 id = __atomic_load_n(monitoring_reload, __ATOMIC_RELAXED);
        if (id != last_id) {
            last_id = id;
            goto start;
        }
        uint32 time_start = time(NULL);
        for (uint32 i = 0; i < details_count; ++i) {
            notification_monitor_details_t *details = &notification_details[i];
            if (!json_object_is_type(details->monitoring_settings, json_type_array) || json_object_array_length(details->monitoring_settings) != sizeof(details->notification_sent))
                continue;
            struct stat data;
            if (fstat(details->fd, &data) == -1 || data.st_mtim.tv_sec <= 0 || data.st_size <= 0)
                continue;
            uint32 now = time(NULL);
            if (now < data.st_mtim.tv_sec)
                continue;
            uint32 last_data_seconds = now - data.st_mtim.tv_sec;
            if (last_data_seconds > DECLARE_DOWN_IF_N_SECONDS_WITHOUT_DATA) { // down
                json_object *element = json_object_array_get_idx(details->monitoring_settings, 0);
                if (!element || !json_object_is_type(element, json_type_int))
                    continue;
                uint64 minutes = json_object_get_uint64(element);
                if ((last_data_seconds - 60) >= (minutes * 60) && !details->notification_sent[0]) {
                    details->notification_sent[0] = true;
                    notify(exec, details->name, details->public_token, "DOWN", true);
                }
                continue;
            }
            if (details->notification_sent[0]) {
                details->notification_sent[0] = false;
                notify(exec, details->name, details->public_token, "DOWN", false);
            }
            int64 pos = data.st_size - (sample_count * sizeof(stats_t));
            if (pos < 0)
                pos = 0;
            double double_totals[6] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };
            uint64 uint_totals[4] = { 0, 0, 0, 0 };
            uint32 total_count = 0, count;
            int32 read_len;
            uint32 last_time = 0;
                uint64 averages[11];
            while (pos < data.st_size && (read_len = pread(details->fd, http_buf, min(sizeof(stats_t) * (sizeof(http_buf) / sizeof(stats_t)), (uint64)(data.st_size - pos)), pos)) > 0) {
                count = read_len / sizeof(stats_t);
                pos += count * sizeof(stats_t);
                total_count += count;
                for (uint16 i = 0; i < count; ++i) {
                    stats_t *element = (stats_t *)http_buf + i;
                    uint32 time_diff = last_time ? element->time - last_time : CONFIG_MEASURE_EVERY_N_SECONDS;
                    if (!time_diff)
                        time_diff = CONFIG_MEASURE_EVERY_N_SECONDS;
                    last_time = element->time;
                    double_totals[0] += TO_DOUBLE_FROM_TWO_UINTS(element->cpu_usage);
                    double_totals[1] += TO_DOUBLE_FROM_TWO_UINTS(element->cpu_iowait);
                    double_totals[2] += TO_DOUBLE_FROM_TWO_UINTS(element->cpu_steal);
                    double_totals[3] += TO_DOUBLE_FROM_TWO_UINTS(element->ram_usage);
                    double_totals[4] += TO_DOUBLE_FROM_TWO_UINTS(element->swap_usage);
                    double_totals[5] += TO_DOUBLE_FROM_TWO_UINTS(element->disk_usage);
                    uint_totals[0] += element->rx_bytes / time_diff;
                    uint_totals[1] += element->tx_bytes / time_diff;
                    uint_totals[2] += (element->read_sectors * SECTOR_SIZE) / time_diff;
                    uint_totals[3] += (element->written_sectors * SECTOR_SIZE) / time_diff;
                }
            }
            if (!total_count)
                continue;
            for (uint8 y = 0; y < 6; ++y) {
                double_totals[y] /= total_count;
                averages[y] = double_totals[y];
                if ((double_totals[y] - averages[y]) >= 0.5)
                    ++averages[y];
            }
            for (uint8 y = 0; y < 4; ++y) {
                uint_totals[y] /= total_count;
                averages[y + 6] = uint_totals[y];
            }
                
                int32 avg_lat = -1;
                if (details->latency_fd != -1) {
                    uint32 valid_target_ids[16];
                    uint32 num_valid_targets = 0;
                    json_object *monitor_obj, *latency_targets_config = NULL;
                    if (json_object_object_get_ex(monitors, details->public_token, &monitor_obj) && json_object_is_type(monitor_obj, json_type_array)) {
                        if (json_object_array_length(monitor_obj) > 6 && (latency_targets_config = json_object_array_get_idx(monitor_obj, 6)) && json_object_is_type(latency_targets_config, json_type_array)) {
                            uint32 num_targets = json_object_array_length(latency_targets_config);
                            for (uint32 v_idx = 0; v_idx < num_targets && v_idx < 16; v_idx++) {
                                json_object *target_obj = json_object_array_get_idx(latency_targets_config, v_idx);
                                json_object *id_obj;
                                if (json_object_object_get_ex(target_obj, "id", &id_obj)) {
                                    valid_target_ids[num_valid_targets++] = json_object_get_int(id_obj);
                                }
                            }
                        }
                    }

                    uint32 lat_file_len = fd_size(details->latency_fd);
                    uint32 cutoff_time = now - (sample_count * 60);
                    int64 scan_pos = lat_file_len - (lat_file_len % sizeof(latency_stat_t));
                    latency_stat_t l_buf[20];
                    int32 lat_read_len;
                    uint64 lat_sum = 0;
                    uint32 lat_valid = 0;
                    while (scan_pos > 0) {
                        uint32 to_read = min((uint32)sizeof(l_buf), (uint32)scan_pos);
                        scan_pos -= to_read;
                        lat_read_len = pread(details->latency_fd, l_buf, to_read, scan_pos);
                        if (lat_read_len <= 0) break;
                        uint32 lcount = lat_read_len / sizeof(latency_stat_t);
                        int stop = 0;
                        for (int32 i = lcount - 1; i >= 0; i--) {
                            int is_valid = 0;
                            for (uint32 v = 0; v < num_valid_targets; v++) {
                                if (valid_target_ids[v] == l_buf[i].id) {
                                    is_valid = 1;
                                    break;
                                }
                            }
                            if (!is_valid) continue;

                            if (l_buf[i].time < cutoff_time) { stop = 1; break; }
                            if (l_buf[i].latency_ms != -1) {
                                lat_sum += l_buf[i].latency_ms;
                                lat_valid++;
                            }
                        }
                        if (stop) break;
                    }
                    if (lat_valid > 0) avg_lat = lat_sum / lat_valid;
                }
                averages[10] = avg_lat > 0 ? avg_lat : 0;

            char *types[] = {
                    "CPU_USAGE", "CPU_IOWAIT", "CPU_STEAL", "RAM_USAGE", "SWAP_USAGE", "DISK_USAGE", "NET_RX", "NET_TX", "DISK_READ", "DISK_WRITE", "LATENCY"
            };
            for (uint8 y = 1; y < sizeof(details->notification_sent); ++y) {
                json_object *element = json_object_array_get_idx(details->monitoring_settings, y);
                uint64 threshold;
                if (!element || !json_object_is_type(element, json_type_int) || !(threshold = json_object_get_uint64(element)))
                    continue;
                if (averages[y - 1] >= threshold) {
                    if (!details->notification_sent[y]) {
                        details->notification_sent[y] = true;
                        notify(exec, details->name, details->public_token, types[y - 1], true);
                    }
                } else if (details->notification_sent[y]) {
                    details->notification_sent[y] = false;
                    notify(exec, details->name, details->public_token, types[y - 1], false);
                }
            }
        }
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0); // reap children
        uint32 now = time(NULL);
        if (now < time_start)
            now = time_start;
        uint32 time_diff = now - time_start;
        if (time_diff >= check_every)
            time_diff = check_every - 1; // sleep at least one second to not overload the system
        sleep(check_every - time_diff);
    }
}

#define CHECK_IF_PERCENTAGE_TOO_BIG(name) name##_before_decimal > 100 || (name##_before_decimal == 100 && name##_after_decimal) || name##_after_decimal > 99

/*
monitoring_server PATH MAX_CHILDREN [LISTEN_PORT]
*/
int main(int argc, char **argv) {
    COMPILE_TIME_CHECKS
    int32 max_children;
    uint16 port = 9999, expected_len, body = 0;
    if ((argc != 3 && argc != 4) || chdir(argv[1]) || !(max_children = (int32)strtoul(argv[2], NULL, 10)) || (argc == 4 && !(port = (uint16)strtoul(argv[3], NULL, 10)))) {
        write(2, SLEN("Missing/invalid argument(s)!\nmonitoring_server PATH MAX_CHILDREN [LISTEN_PORT]\nFor details, look into the README.\n"));
        return 99;
    }
    signal(SIGPIPE, SIG_IGN);
    monitoring_reload = mmap(NULL, CACHELINE + CACHELINE + CACHELINE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (monitoring_reload == MAP_FAILED)
        return 2;
    __atomic_store_n(monitoring_reload, (uint32)0, __ATOMIC_RELAXED);
    int pid = fork();
    if (pid == -1)
        return 3;
    if (!pid)
        notifications_proc();
    proc = PROC_WEB;
    data_json_changed = (void *)((uint8 *)monitoring_reload + CACHELINE);
    admin_proc = (void *)((uint8 *)monitoring_reload + CACHELINE + CACHELINE);
    __atomic_store_n(data_json_changed, false, __ATOMIC_RELAXED);
    __atomic_store_n(admin_proc, false, __ATOMIC_RELAXED);
    struct sigaction sa;
    sa.sa_handler = (sighandler_t)sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    __atomic_store_n(&children, 0, __ATOMIC_RELAXED);
    int sock, opt = 1;
    struct sockaddr client_addr;
    struct sockaddr_in listen_to;
    net_header_t *ptr_header;
    stats_t *ptr_stats;
    socklen_t addrlen = sizeof(client_addr);
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return 4;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&listen_to, 0, sizeof(listen_to));
    listen_to.sin_family = AF_INET;
#ifdef LISTEN_ALL
    listen_to.sin_addr.s_addr = inet_addr("0.0.0.0");
#else
    listen_to.sin_addr.s_addr = inet_addr("127.0.0.1");
#endif
    listen_to.sin_port = htons(port);
    if (bind(sock, (struct sockaddr *)&listen_to, sizeof(listen_to)) < 0)
        return 5;
    if (listen(sock, SERVER_LISTEN_BACKLOG) < 0)
        return 6;
    while (!parse_data_json())
        usleep(500);
    status_page_fd = open_with_retries("status.html", O_RDONLY);
    monitor_page_fd = open_with_retries("monitor.html", O_RDONLY);
    admin_page_fd = open_with_retries("admin.html", O_RDONLY);
    favicon_ico_fd = open("favicon.ico", O_RDONLY);
    json_c_set_serialization_double_format("%.2f", JSON_C_OPTION_GLOBAL);
    for (;;) {
        if (close_fds_count)
            check_close_fds();
        if (__atomic_load_n(data_json_changed, __ATOMIC_RELAXED)) {
            while (!parse_data_json())
                usleep(500);
            __atomic_store_n(data_json_changed, false, __ATOMIC_RELAXED);
            uint32 id = time(NULL);
            if (__atomic_load_n(monitoring_reload, __ATOMIC_RELAXED) == id)
                ++id;
            __atomic_store_n(monitoring_reload, id, __ATOMIC_RELAXED);
        }
        if ((client = syscall(__NR_accept4, sock, &client_addr, &addrlen, SOCK_NONBLOCK)) < 0)
            continue;
        unsigned int timeout = 50; // 50 ms, should be more than enough as the reverse proxy should be on the same machine
        struct timeval timeout_struct = { .tv_sec = 0, .tv_usec = 50000 };
        if (setsockopt(client, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, sizeof(timeout)) ||
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout_struct, sizeof(timeout_struct)) ||
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout_struct, sizeof(timeout_struct)) ||
            !sock_ready(client, true, 1) || (len = read(client, http_buf, sizeof(http_buf) - 1)) < (int32)strlen("GET / HTTP/1.1\r\nHost:\r\n\r\n"))
            goto cont;
        bool admin = false;
        if (http_buf[1] == 'E') { // GET
            if (http_buf_compare("GET /", "admin") && http_buf[strlen("GET /admin ") - 1] != ' ' && http_buf[strlen("GET /admin/ ") - 1] != ' ')
                goto admin;
            goto fork;
        }
        if (http_buf[1] != 'O') // POST
            goto cont;
        if (http_buf_compare("POST /", "submit") || http_buf_compare("POST /", "latency") || http_buf_compare("POST /", "latency_config")) {
            body = get_http_body();
            if (!body) {
                if (sock_ready(client, true, 1)) {
                    int tmp = read(client, http_buf + len, sizeof(http_buf) - len);
                    if (tmp <= 0) goto cont;
                    len += tmp;
                    body = get_http_body();
                    if (!body || len == body) goto cont;
                } else goto cont;
            }
            if (len == body && sock_ready(client, true, 1)) {
                len = read(client, http_buf, sizeof(http_buf));
                if (len == -1) goto cont;
                body = 0;
            }
        }
        if (http_buf_compare("POST /", "submit")) {
            if ((uint32)len < body + sizeof(net_header_t) + sizeof(details_t))
                goto cont;
            ptr_header = (net_header_t *)(http_buf + body);
            for (uint8 i = 0; i < 32; ++i)
                if (!isxdigit(ptr_header->token[i]))
                    goto cont;
            monitor_details_t *monitor;
            if (ptr_header->token[32] || !(monitor = get_monitor_details_by_private(ptr_header->token)))
                goto cont;
            if (ptr_header->version == 1) {
                expected_len = sizeof(net_header_t);
                if (ptr_header->includes_details)
                    expected_len += sizeof(details_t);
                expected_len += sizeof(stats_t) * ptr_header->stats_count;
                if (expected_len + body != (uint32)len)
                    goto cont;
                uint32 last_time = monitor->was_online ? monitor->stats.time : 0, error_if_bigger_than = time(NULL) + 100;
                ptr_stats = (stats_t *)(http_buf + body + sizeof(net_header_t));
                if (ptr_header->includes_details)
                    ptr_stats = (stats_t *)((uint8 *)ptr_stats + sizeof(details_t));
                for (uint8 i = 0; i < ptr_header->stats_count; ++i) {
                    if (ptr_stats[i].time <= last_time // Likely resubmission of data because the success response wasn't received => don't save but respond with a success message (problematic in case of time adjustment but there's no easy correct way to handle this, and it would likely mean that data would have to be removed from the file (how much?), so this is the most reasonable I think.)
                        || ptr_stats[i].time > error_if_bigger_than // if there's a significant time difference, don't save the data
                        || CHECK_IF_PERCENTAGE_TOO_BIG(ptr_stats[i].cpu_usage)
                        || CHECK_IF_PERCENTAGE_TOO_BIG(ptr_stats[i].cpu_iowait)
                        || CHECK_IF_PERCENTAGE_TOO_BIG(ptr_stats[i].cpu_steal)
                        || CHECK_IF_PERCENTAGE_TOO_BIG(ptr_stats[i].ram_usage)
                        || CHECK_IF_PERCENTAGE_TOO_BIG(ptr_stats[i].swap_usage)
                        || CHECK_IF_PERCENTAGE_TOO_BIG(ptr_stats[i].disk_usage)
                    )
                        goto success;
                }
                if ((len = write(monitor->fd, ptr_stats, sizeof(stats_t) * ptr_header->stats_count)) != -1) {
                    if (len < (int32)(sizeof(stats_t) * ptr_header->stats_count)) {
                        usleep(1000);
                        int32 tmp = write(monitor->fd, ((uint8 *)ptr_stats) + len, (sizeof(stats_t) * ptr_header->stats_count) - len);
                        if (tmp > 0)
                            len += tmp;
                    }
                    if ((uint32)len != (sizeof(stats_t) * ptr_header->stats_count)) {
                        uint32 file_len;
                        if (len && (file_len = fd_size(monitor->fd)) >= (uint32)len)
                            ftruncate(monitor->fd, file_len - len); // try to remove the part that was already written
                        goto cont;
                    }
                } else
                    goto cont;
                for (uint8 i = 0; i < ptr_header->stats_count; ++i) { // not done in the above loop because only now all data is validated and saved
                    monitor->rx_total += ptr_stats[i].rx_bytes;
                    monitor->tx_total += ptr_stats[i].tx_bytes;
                    monitor->sectors_read_total += ptr_stats[i].read_sectors;
                    monitor->sectors_written_total += ptr_stats[i].written_sectors;
                }
                if (ptr_header->includes_details) {
                    monitor->was_online = true;
                    memcpy(&monitor->details, http_buf + body + sizeof(net_header_t), sizeof(details_t));
                    memcpy(&monitor->stats, ptr_stats + ptr_header->stats_count - 1, sizeof(stats_t));
                    if (ptr_stats[ptr_header->stats_count - 1].time - last_time > (uint32)min(CONFIG_MEASURE_EVERY_N_SECONDS * 1.2, CONFIG_MEASURE_EVERY_N_SECONDS + 1))
                        monitor->time_diff = (CONFIG_MEASURE_EVERY_N_SECONDS + 1);
                    else
                        monitor->time_diff = ptr_stats[ptr_header->stats_count - 1].time - last_time;
                }
success:
                if (sock_ready(client, false, 1))
                    write(client, SLEN("HTTP/1.1 200\r\nContent-Length: 1\r\nConnection: close\r\n\r\n1"));
            }
            goto cont;
        }
        if (http_buf_compare("POST /", "latency_config")) {
            if ((uint32)len < (uint32)(body + 32)) goto cont;
            char token[33];
            memcpy(token, http_buf + body, 32);
            token[32] = '\0';
            
            monitor_details_t *monitor = get_monitor_details_by_private(token);
            if (!monitor) goto cont;
            
            json_object *monitor_obj, *latency_monitors;
            if (json_object_object_get_ex(monitors, monitor->public_token, &monitor_obj) &&
                json_object_is_type(monitor_obj, json_type_array) &&
                (latency_monitors = json_object_array_get_idx(monitor_obj, 6)) != NULL &&
                json_object_is_type(latency_monitors, json_type_array)) {
                
                uint32 count = json_object_array_length(latency_monitors);
                uint32 response_len = sizeof(uint32) + count * sizeof(latency_target_t);
                
                uint16 hdr_len = 0;
                str_append(http_buf, &hdr_len, "HTTP/1.1 200\r\nContent-Length: ");
                str_append_uint(http_buf, &hdr_len, response_len);
                str_append(http_buf, &hdr_len, "\r\nConnection: close\r\n\r\n");
                
                client_write_len(http_buf, hdr_len);
                client_write_len((char*)&count, sizeof(uint32));
                
                for (uint32 i = 0; i < count; i++) {
                    json_object *lm = json_object_array_get_idx(latency_monitors, i);
                    json_object *j_id, *j_type, *j_port, *j_target;
                    latency_target_t lt;
                    memset(&lt, 0, sizeof(lt));
                    if (json_object_object_get_ex(lm, "id", &j_id)) lt.id = json_object_get_int(j_id);
                    if (json_object_object_get_ex(lm, "type", &j_type)) {
                        const char *type_str = json_object_get_string(j_type);
                        if (strcmp(type_str, "icmp") == 0) lt.type = 1;
                        else lt.type = 0;
                    }
                    if (json_object_object_get_ex(lm, "port", &j_port)) lt.port = json_object_get_int(j_port);
                    if (json_object_object_get_ex(lm, "target", &j_target)) strncpy(lt.target, json_object_get_string(j_target), sizeof(lt.target) - 1);
                    client_write_len((char*)&lt, sizeof(latency_target_t));
                }
            } else {
                uint32 zero_count = 0;
                client_write("HTTP/1.1 200\r\nContent-Length: 4\r\nConnection: close\r\n\r\n");
                client_write_len((char*)&zero_count, 4);
            }
            goto cont;
        }
        if (http_buf_compare("POST /", "latency")) {
            if ((uint32)len < body + sizeof(latency_req_header_t)) goto cont;
            latency_req_header_t *l_header = (latency_req_header_t *)(http_buf + body);
            char token[33];
            memcpy(token, l_header->token, 32);
            token[32] = '\0';
            monitor_details_t *monitor = get_monitor_details_by_private(token);
            if (!monitor) goto cont;
            if (l_header->count > (sizeof(http_buf) - body - sizeof(latency_req_header_t)) / sizeof(latency_stat_t)) goto cont;
            if ((uint32)len < body + sizeof(latency_req_header_t) + l_header->count * sizeof(latency_stat_t)) goto cont;
            latency_stat_t *l_stats = (latency_stat_t *)(http_buf + body + sizeof(latency_req_header_t));
            if (monitor->latency_fd != -1) {
                if (write(monitor->latency_fd, l_stats, sizeof(latency_stat_t) * l_header->count) == -1) {}
            }
            client_write("HTTP/1.1 200\r\nContent-Length: 1\r\nConnection: close\r\n\r\n1");
            goto cont;
        }
        if (http_buf_compare("POST ", "/admin")) {
admin:
            if ((uint32)len <= strlen("GET /admin/ HTTP/1.1\r\nHost:\r\n\r\n"))
                goto cont;
            if (http_buf[1] == 'O' && http_buf_compare("POST /admin", "/login") && (uint32)len >= strlen("POST /admin/login HTTP/1.1\r\n\r\n{\"hash\":\"\"}") + 64) {
                admin = ADMIN_STATE_LOGIN;
                goto fork;
            }
            if (__atomic_load_n(data_json_changed, __ATOMIC_RELAXED)) { // if the admin process was still running when it was last checked
                while (!parse_data_json());
                __atomic_store_n(data_json_changed, false, __ATOMIC_RELAXED);
                uint32 id = time(NULL);
                if (__atomic_load_n(monitoring_reload, __ATOMIC_RELAXED) == id)
                    ++id;
                __atomic_store_n(monitoring_reload, id, __ATOMIC_RELAXED);
            }
            if (!is_logged_in() || __atomic_load_n(admin_proc, __ATOMIC_RELAXED))
                goto cont;
            __atomic_store_n(admin_proc, true, __ATOMIC_RELAXED); // no CAS needed because if no admin process is running, this variable won't be modified from anywhere else
            admin = true;
        } else
            goto cont;
fork:
        if (__atomic_load_n(&children, __ATOMIC_RELAXED) >= max_children)
            goto cont;
        if ((pid = syscall(__NR_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0)) > 0) {
            __atomic_add_fetch(&children, 1, __ATOMIC_RELAXED);
            continue;
        } else {
            if (!pid) {
                if (!admin) { // the fds in details cannot be closed while the admin process is doing work as only the admin process can cause a re-load of data.json and therefore a closing of them; other children MAY NOT use ANY syscalls causing fds to be allocated as they may terminate before they can close them.
                    struct itimerval timer = { .it_value = { .tv_sec = 10, .tv_usec = 0 }, .it_interval = { .tv_sec = 0, .tv_usec = 0 } }; // terminate after 10 seconds to ensure fds aren't used anymore (and it doesn't make much sense to run longer as the HTTP request will likely have timeouted by then)
                    if (setitimer(ITIMER_REAL, &timer, NULL) == -1)
                        return 1;
                    signal(SIGALRM, (sighandler_t)sigalrm_handler);
                    process_request();
                } else
                    admin_process_request(admin);
                close(client);
                _exit(0); // don't clean up
            } else if (admin) // pid < 0 => fork failed
                __atomic_store_n(admin_proc, false, __ATOMIC_RELAXED);
        }
cont:
        close(client);
    }
}
