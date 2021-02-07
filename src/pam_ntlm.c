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
    uid_t uid, oeuid;
    gid_t gid, oegid;
    char key_name[20];

    status = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&pass);

    if (status != PAM_SUCCESS)
        return status;

    status = pam_get_item(pamh, PAM_USER, (const void**)&user);
    if (status == PAM_SUCCESS) {
        struct passwd* pwd = getpwnam(user);
        if (pwd) {
            uid = pwd->pw_uid;
            gid = pwd->pw_gid;
        } else {
            pam_syslog(pamh, LOG_ERR, "getpwnam returned NULL for %s", user);
            return PAM_SUCCESS;
        }
    } else {
        pam_syslog(pamh, LOG_ERR, "Error getting name of user logging in.");
        return PAM_SUCCESS;
    }

    // FIXME - make sure not done if previous module failed

    // FIXME - calculate NT hash

    // FIXME - make sure removed when logging out
    // FIXME - make sure updated when password changed

    sprintf(key_name, "nthash.%u", uid);

    oeuid = geteuid();
    oegid = getegid();

    if (seteuid(uid)) {
        pam_syslog(pamh, LOG_ERR, "seteuid failed (error %u)", errno);
        return PAM_SUCCESS;
    }

    if (setegid(gid)) {
        seteuid(oeuid);
        pam_syslog(pamh, LOG_ERR, "seteuid failed (error %u)", errno);
        return PAM_SUCCESS;
    }

    // FIXME - get user keyring

    // FIXME - payload should be NT hash
    key = add_key("user", key_name, "hello", 5, KEY_SPEC_USER_KEYRING);

    if (key == -1) {
        setegid(oegid);
        seteuid(oeuid);
        pam_syslog(pamh, LOG_ERR, "Error adding nthash to keyring (add_key returned error %u)", errno);
        return PAM_SUCCESS;
    }

    setegid(oegid);
    seteuid(oeuid);

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
