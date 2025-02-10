/*
 * @Author: wangqi wangqi@zhizhangyi.com
 * @Date: 2024-12-10 14:07:57
 * @LastEditors: wangqi wangqi@zhizhangyi.com
 * @LastEditTime: 2024-12-11 18:06:35
 * @FilePath: \1210\changepayload\src\logging.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include "logging.h"
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <pthread.h>

static log_level_t current_level = LOG_LEVEL_INFO;
static FILE *log_fp = NULL;
static const char *log_path = "/tmp/changepayload.log";
static const size_t MAX_LOG_SIZE = 100 * 1024 * 1024; // 100MB
pthread_mutex_t log_mutex; // 定义一个互斥锁

log_level_t log_get_level() {
    return current_level;
}

void log_rotate_if_needed() {
    if (!log_fp) return;

    fflush(log_fp);
    struct stat st;
    if (fstat(fileno(log_fp), &st) == 0) {
        if ((size_t)st.st_size > MAX_LOG_SIZE) {
            fclose(log_fp);
            char old_path[256];
            snprintf(old_path, sizeof(old_path), "%s.old", log_path);
            rename(log_path, old_path);
            log_fp = fopen(log_path, "a");
            if (!log_fp) {
                log_fp = stderr;
            }
        }
    }
}

void log_init(log_level_t level) {
    current_level = level;
    log_fp = fopen(log_path, "a");
    if (!log_fp) {
        log_fp = stderr;
    }
    pthread_mutex_init(&log_mutex, NULL); // 初始化互斥锁
}

void log_msg(log_level_t level, const char *fmt, ...) {
    if (level > current_level) return;
    if (!log_fp) log_fp = stderr;

    pthread_mutex_lock(&log_mutex); // 在写入日志之前加锁
    const char *level_str = NULL;
    switch(level) {
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        case LOG_LEVEL_INFO: level_str = "INFO"; break;
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    va_list args;
    va_start(args, fmt);
    fprintf(log_fp, "[%s][%s] ", time_buf, level_str);
    vfprintf(log_fp, fmt, args);
    fprintf(log_fp, "\n");
    va_end(args);
    fflush(log_fp);

    log_rotate_if_needed();

    pthread_mutex_unlock(&log_mutex); // 完成写入后解锁
}

void log_close() {
    pthread_mutex_destroy(&log_mutex); // 销毁互斥锁
}
