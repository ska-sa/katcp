#ifndef LOCK_H
#define LOCK_H

#define UNLOCKED    0
#define LOCKED      1


struct device_lock{
    int status;
    int key;
    char *owner;
};

int testlock();
int lockdev_cmd(struct katcp_dispatch *d);
int lockgetkey_cmd(struct katcp_dispatch *d);
int unlockdev_cmd(struct katcp_dispatch *d, int argc);

#endif
