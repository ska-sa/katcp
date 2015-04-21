#include <stdlib.h>
#include <katcp.h>
#include <katpriv.h>
#include <time.h>

#include "lock.h"

static struct device_lock lock = { .status=UNLOCKED };

int testlock(){
    return lock.status;
}

int lockdev_cmd(struct katcp_dispatch *d){

    if (lock.status == LOCKED){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "device already locked");
        return KATCP_RESULT_FAIL;
    }

    srand(time(NULL));
    lock.key = rand();
    lock.owner = d->d_name;
    lock.status = LOCKED;

    prepend_reply_katcp(d);
    append_string_katcp(d, KATCP_FLAG_STRING, KATCP_OK);
    append_hex_long_katcp(d, KATCP_FLAG_XLONG | KATCP_FLAG_LAST, lock.key);
    return KATCP_RESULT_OWN;
}

int lockgetkey_cmd(struct katcp_dispatch *d){

    if (lock.status != LOCKED){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "device is not locked");
        return KATCP_RESULT_FAIL;
    }

    prepend_reply_katcp(d);
    append_string_katcp(d, KATCP_FLAG_STRING, KATCP_OK);
    append_hex_long_katcp(d, KATCP_FLAG_XLONG | KATCP_FLAG_LAST, lock.key);
    return KATCP_RESULT_OWN;
}

int unlockdev_cmd(struct katcp_dispatch *d, int argc){

    char *temp;
    int tempkey;

    if (lock.status == UNLOCKED){
        return KATCP_RESULT_OK;
    }

    if (argc != 2){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "invalid number of arguements");
        return KATCP_RESULT_INVALID;
    }

    temp = arg_string_katcp(d, 1);
    /*tempkey = atoi(temp);*/
    tempkey = strtol(temp, NULL, 16);

    if (tempkey != lock.key){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "invalid key");
        return KATCP_RESULT_FAIL;
    }

#if 0
    if ((key != lock.key) && (d->d_name != lock.owner)){
        return -1;
    }
#endif

    lock.status = UNLOCKED;
    return KATCP_RESULT_OK;
}

