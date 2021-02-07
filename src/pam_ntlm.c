#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <syslog.h>
#include <keyutils.h>
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <uchar.h>
#include <unicode/ucnv.h>
#include <stdlib.h>
#include <string.h>

static char16_t* utf8_to_utf16(pam_handle_t* pamh, const char* s, size_t* retlen) {
    UErrorCode status = U_ZERO_ERROR;
    UConverter* conv = ucnv_open("UTF-8", &status);
    size_t s_len, len;
    char16_t* ret;

    if (U_FAILURE(status)) {
        pam_syslog(pamh, LOG_ERR, "ucnv_open failed for code page UTF-8 (%s)", u_errorName(status));
        return NULL;
    }

    s_len = strlen(s);

    len = s_len * 2; // each input byte might expand to 2 char16_ts
    ret = malloc(len * sizeof(char16_t));

    if (!ret) {
        pam_syslog(pamh, LOG_ERR, "malloc failed");
        ucnv_close(conv);
        return NULL;
    }

    len = (size_t)ucnv_toUChars(conv, ret, (int32_t)len, s, (int32_t)s_len, &status);

    ucnv_close(conv);

    *retlen = len * sizeof(char16_t);

    return ret;
}

__attribute__ ((visibility ("default")))
int pam_sm_authenticate(pam_handle_t* pamh, __attribute__((unused)) int flags,
                        __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    int status;
    const char* pass;
    const char* user = NULL;
    key_serial_t key;
    char16_t* pw_utf16;
    size_t len;

    status = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&pass);

    if (status != PAM_SUCCESS)
        return status;

    status = pam_get_item(pamh, PAM_USER, (const void**)&user);
    if (status != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Error getting name of user logging in.");
        return PAM_SUCCESS;
    }

    // FIXME - make sure not done if previous module failed

    // FIXME - calculate NT hash by MD4'ing UTF-16

    // FIXME - make sure updated when password changed
    pw_utf16 = utf8_to_utf16(pamh, "hello", &len); // FIXME - should be password
    if (!pw_utf16)
        return PAM_SUCCESS;

    // FIXME - payload should be NT hash
    key = add_key("user", "nthash", pw_utf16, len, KEY_SPEC_SESSION_KEYRING);

    if (key == -1) {
        pam_syslog(pamh, LOG_ERR, "Error adding nthash to keyring (add_key returned error %i)", errno);
        free(pw_utf16);
        return PAM_SUCCESS;
    }

    free(pw_utf16);

    pam_syslog(pamh, LOG_ERR, "Added nthash key %u for %s.", key, user ? user : "(unknown user)");

    // FIXME

    return PAM_SUCCESS;
}

__attribute__ ((visibility ("default")))
int pam_sm_setcred(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                   __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_acct_mgmt(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                     __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_open_session(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                        __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}

__attribute__ ((visibility ("default")))
int pam_sm_close_session(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                         __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_SUCCESS;
}

__attribute__ ((visibility ("default")))
int pam_sm_chauthtok(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                     __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    return PAM_IGNORE;
}
