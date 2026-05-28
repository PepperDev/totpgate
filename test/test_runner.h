#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT_INT_EQ(a, b) \
    do { \
        int _a = (a); \
        int _b = (b); \
        if (_a != _b) { \
            fprintf(stderr, "ASSERT_INT_EQ FAIL: %s:%d: %d != %d\n", \
                    __FILE__, __LINE__, _a, _b); \
            exit(1); \
        } \
    } while (0)

#define ASSERT_STREQ(a, b) \
    do { \
        const char *_a = (a); \
        const char *_b = (b); \
        if (strcmp(_a, _b) != 0) { \
            fprintf(stderr, "ASSERT_STREQ FAIL: %s:%d: \"%s\" != \"%s\"\n", \
                    __FILE__, __LINE__, _a, _b); \
            exit(1); \
        } \
    } while (0)

#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "ASSERT_TRUE FAIL: %s:%d\n", \
                    __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

#define ASSERT_FALSE(expr) \
    do { \
        if ((expr)) { \
            fprintf(stderr, "ASSERT_FALSE FAIL: %s:%d\n", \
                    __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

#endif
