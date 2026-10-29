#include "../include/yrscan.h"
#include "../include/logger.h"

#include <stdio.h>

#ifdef HAVE_YARA

#include <yara.h>
#include <string.h>

static int yara_callback(YR_SCAN_CONTEXT *ctx, int message, void *message_data, void *user_data) {
    (void)ctx;
    (void)user_data;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        printf("    [YARA] rule matched: %s\n", rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

int yrscan_file(const char *rules_path, const char *target_path) {
    if (yr_initialize() != ERROR_SUCCESS) {
        log_message(LOG_ERROR, "YARA initialization failed.");
        return -1;
    }

    YR_COMPILER *compiler = NULL;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        yr_finalize();
        log_message(LOG_ERROR, "YARA compiler creation failed.");
        return -1;
    }

    FILE *rf = fopen(rules_path, "r");
    if (!rf) {
        log_message(LOG_ERROR, "Cannot open rules file: %s", rules_path);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    int errors = yr_compiler_add_file(compiler, rf, NULL, rules_path);
    fclose(rf);
    if (errors > 0) {
        log_message(LOG_ERROR, "YARA rule compilation produced %d error(s).", errors);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    YR_RULES *rules = NULL;
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    log_message(LOG_INFO, "Scanning %s with rules %s", target_path, rules_path);
    yr_rules_scan_file(rules, target_path, 0, yara_callback, NULL, 0);

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();
    return 0;
}

#else

int yrscan_file(const char *rules_path, const char *target_path) {
    (void)rules_path;
    (void)target_path;
    log_message(LOG_ERROR, "This build was compiled without YARA support.");
    return -1;
}

#endif
