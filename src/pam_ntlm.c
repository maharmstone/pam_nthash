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

__attribute__ ((visibility ("default")))
int pam_sm_authenticate(__attribute__((unused)) pam_handle_t* pamh, __attribute__((unused)) int flags,
                        __attribute__((unused)) int argc, __attribute__((unused)) const char** argv) {
    int status;
    const char* pass;
    const char* user = NULL;
    key_serial_t key;

    status = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&pass);

    if (status != PAM_SUCCESS)
        return status;

    status = pam_get_item(pamh, PAM_USER, (const void**)&user);
    if (status != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Error getting name of user logging in.");
        return PAM_SUCCESS;
    }

    // FIXME - make sure not done if previous module failed

    // FIXME - calculate NT hash

    // FIXME - make sure updated when password changed

    // FIXME - payload should be NT hash
    key = add_key("user", "nthash", "hello", 5, KEY_SPEC_SESSION_KEYRING);

    if (key == -1) {
        pam_syslog(pamh, LOG_ERR, "Error adding nthash to keyring (add_key returned error %i)", errno);
        return PAM_SUCCESS;
    }

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
