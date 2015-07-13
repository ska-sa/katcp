#ifndef DHCP_H
#define DHCP_H

typedef enum {DHCPDISCOVER=1, DHCPOFFER, DHCPREQUEST,
        DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE, DHCPINFORM} MSG_TYPE;

//extern struct getap_state;

int tap_dhcp_cmd(struct katcp_dispatch *d, int argc);
int dhcp_msg(struct getap_state *gs, MSG_TYPE mt);

#endif
