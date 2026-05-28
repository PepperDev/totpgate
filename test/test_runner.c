#include "test_runner.h"

/* test groups */
extern const test_case_t encode_tests[];
extern const test_case_t sha1_tests[];
extern const test_case_t hmac_tests[];
extern const test_case_t totp_tests[];
extern const test_case_t udp_tests[];
extern const test_case_t auth_tests[];

static const test_group_t all_groups[] = {
    { "encode", encode_tests },
    { "sha1", sha1_tests },
    { "hmac", hmac_tests },
    { "totp", totp_tests },
    { "udp", udp_tests },
    { "auth", auth_tests },
};

int main(void)
{
    int passed = 0;
    int failed = 0;
    int gi;

    for (gi = 0; gi < (int)(sizeof(all_groups) / sizeof(all_groups[0])); gi++) {
        const test_group_t *g = &all_groups[gi];
        int ti;

        printf("%s:\n", g->name);
        for (ti = 0; g->tests[ti].fn != NULL; ti++) {
            printf("  %s ... ", g->tests[ti].name);
            g->tests[ti].fn();
            printf("OK\n");
            passed++;
        }
    }

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed;
}
