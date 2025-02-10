/*
 * @Author: wangqi wangqi@zhizhangyi.com
 * @Date: 2024-12-10 14:07:57
 * @LastEditors: wangqi wangqi@zhizhangyi.com
 * @LastEditTime: 2024-12-11 18:08:29
 * @FilePath: \1210\changepayload\include\logging.h
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>

typedef enum {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

void log_init(log_level_t level);
void log_close();
void log_rotate_if_needed();
log_level_t log_get_level();
void log_msg(log_level_t level, const char *fmt, ...);

#define LOG_ERR(fmt, ...)  log_msg(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_msg(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_msg(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

/** 
// 宏方便使用
#define LOG_INFO(fmt, ...) log_msg(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  log_msg(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) log_msg(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)
#endif

void log_close();
*/
#endif
