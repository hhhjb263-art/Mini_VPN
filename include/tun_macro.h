#pragma once
#include <cstdio>
#include <cassert>

//==================== 编译模式区分 ====================
#ifdef _DEBUG
#define TUN_DEBUG_MODE 1
#else
#define TUN_DEBUG_MODE 0
#endif

// 详细日志开关
#if TUN_DEBUG_MODE
#define TUN_DEBUG_LOG 1
#define TUN_VERBOSE_LOG 1
#else
#define TUN_DEBUG_LOG 0
#define TUN_VERBOSE_LOG 0
#endif

//==================== 断言宏 ====================
#if TUN_DEBUG_MODE
#define TUN_ASSERT(expr, msg) \
do { \
    if (!(expr)) { \
        fprintf(stderr, "[ASSERT FAIL] %s:%d %s\n", __FILE__, __LINE__, msg); \
        assert(false); \
    } \
} while(0)
#define TUN_API_CHECK(expr, retVal) TUN_ASSERT(expr, "api param invalid"); if(!(expr)) return retVal;
#else
// Release 直接删除断言，不阻塞程序
#define TUN_ASSERT(expr, msg) ((void)0)
#define TUN_API_CHECK(expr, retVal) if(!(expr)) return retVal;
#endif

//==================== 日志分级 ====================
#define LOG_FATAL(fmt, ...)  fprintf(stderr, "[FATAL] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)  fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)   fprintf(stdout, "[WARN]  " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)   fprintf(stdout, "[INFO]  " fmt "\n", ##__VA_ARGS__)

#if TUN_DEBUG_LOG
#define LOG_DEBUG(fmt, ...)  fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) ((void)0)
#endif

#if TUN_VERBOSE_LOG
#define LOG_TRACE(fmt, ...)  fprintf(stdout, "[TRACE] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_TRACE(fmt, ...) ((void)0)
#endif