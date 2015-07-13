#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include "tcpborphserver3.h"
#include "tg.h"
#include "dhcp.h"

/*indices of start of specific parameters in frame, contains suffix "_I" */
/*zero indexed*/


#define ETH_FRAME_START_INDEX       0
#define ETH_DST_OFFSET              0
#define ETH_DST_LEN                 6
#define ETH_SRC_OFFSET              (ETH_DST_OFFSET + ETH_DST_LEN)  //6
#define ETH_SRC_LEN                 6
#define ETH_FRAME_TYPE_OFFSET       (ETH_SRC_OFFSET + ETH_SRC_LEN)  //12
#define ETH_FRAME_TYPE_LEN          2

#define ETH_FRAME_TOTAL_LEN         (ETH_FRAME_TYPE_OFFSET + ETH_FRAME_TYPE_LEN)

#define IP_FRAME_START_INDEX        (ETH_FRAME_START_INDEX + ETH_FRAME_TOTAL_LEN)
#define IP_V_HIL_OFFSET             0
#define IP_V_HIL_LEN                1
#define IP_TOS_OFFSET               (IP_V_HIL_OFFSET + IP_V_HIL_LEN)  //1
#define IP_TOS_LEN                  1
#define IP_TLEN_OFFSET              (IP_TOS_OFFSET + IP_TOS_LEN)  //2
#define IP_TLEN_LEN                 2
#define IP_ID_OFFSET                (IP_TLEN_OFFSET + IP_TLEN_LEN) //4
#define IP_ID_LEN                   2
#define IP_FLAG_FRAG_OFFSET         (IP_ID_OFFSET + IP_ID_LEN) //6
#define IP_FLAG_FRAG_LEN            2
#define IP_TTL_OFFSET               (IP_FLAG_FRAG_OFFSET + IP_FLAG_FRAG_LEN) //8 
#define IP_TTL_LEN                  1 
#define IP_PROT_OFFSET              (IP_TTL_OFFSET + IP_TTL_LEN) //9
#define IP_PROT_LEN                 1 
#define IP_CHKSM_OFFSET             (IP_PROT_OFFSET + IP_PROT_LEN) //10
#define IP_CHKSM_LEN                2
#define IP_SRC_OFFSET               (IP_CHKSM_OFFSET + IP_CHKSM_LEN)//12
#define IP_SRC_LEN                  4
#define IP_DST_OFFSET               (IP_SRC_OFFSET + IP_SRC_LEN)//16
#define IP_DST_LEN                  4

#define IP_FRAME_TOTAL_LEN          (IP_DST_OFFSET + IP_DST_LEN)

#define UDP_FRAME_START_INDEX       (IP_FRAME_START_INDEX + IP_FRAME_TOTAL_LEN) //34 
#define UDP_SRC_PORT_OFFSET         0
#define UDP_SRC_PORT_LEN            2
#define UDP_DST_PORT_OFFSET         (UDP_SRC_PORT_OFFSET + UDP_SRC_PORT_LEN) //2
#define UDP_DST_PORT_LEN            2
#define UDP_ULEN_OFFSET             (UDP_DST_PORT_OFFSET + UDP_DST_PORT_LEN) //4
#define UDP_ULEN_LEN                2
#define UDP_CHKSM_OFFSET            (UDP_ULEN_OFFSET + UDP_ULEN_LEN) //6
#define UDP_CHKSM_LEN               2

#define UDP_FRAME_TOTAL_LEN         (UDP_CHKSM_OFFSET + UDP_CHKSM_LEN)

#define BOOTP_FRAME_START_INDEX     (UDP_FRAME_START_INDEX + UDP_FRAME_TOTAL_LEN) //42
#define BOOTP_OPTYPE_OFFSET         0
#define BOOTP_OPTYPE_LEN            1
#define BOOTP_HWTYPE_OFFSET         (BOOTP_OPTYPE_OFFSET + BOOTP_OPTYPE_LEN) //1
#define BOOTP_HWTYPE_LEN            1
#define BOOTP_HWLEN_OFFSET          (BOOTP_HWTYPE_OFFSET + BOOTP_HWTYPE_LEN) //2
#define BOOTP_HWLEN_LEN             1
#define BOOTP_HOPS_OFFSET           (BOOTP_HWLEN_OFFSET + BOOTP_HWLEN_LEN) //3
#define BOOTP_HOPS_LEN              1
#define BOOTP_XID_OFFSET            (BOOTP_HOPS_OFFSET + BOOTP_HOPS_LEN) //4
#define BOOTP_XID_LEN               4
#define BOOTP_SEC_OFFSET            (BOOTP_XID_OFFSET + BOOTP_XID_LEN) //8
#define BOOTP_SEC_LEN               2
#define BOOTP_FLAGS_OFFSET          (BOOTP_SEC_OFFSET + BOOTP_SEC_LEN) //10
#define BOOTP_FLAGS_LEN             2
#define BOOTP_CIPADDR_OFFSET        (BOOTP_FLAGS_OFFSET + BOOTP_FLAGS_LEN) //12
#define BOOTP_CIPADDR_LEN           4
#define BOOTP_YIPADDR_OFFSET        (BOOTP_CIPADDR_OFFSET + BOOTP_CIPADDR_LEN) //16
#define BOOTP_YIPADDR_LEN           4
#define BOOTP_SIPADDR_OFFSET        (BOOTP_YIPADDR_OFFSET + BOOTP_YIPADDR_LEN) //20
#define BOOTP_SIPADDR_LEN           4
#define BOOTP_GIPADDR_OFFSET        (BOOTP_SIPADDR_OFFSET + BOOTP_SIPADDR_LEN) //24
#define BOOTP_GIPADDR_LEN           4
#define BOOTP_CHWADDR_OFFSET        (BOOTP_GIPADDR_OFFSET + BOOTP_GIPADDR_LEN) //28
#define BOOTP_CHWADDR_LEN           16
#define BOOTP_SNAME_OFFSET          (BOOTP_CHWADDR_OFFSET + BOOTP_CHWADDR_LEN)//44
#define BOOTP_SNAME_LEN             64
#define BOOTP_FILE_OFFSET           (BOOTP_SNAME_OFFSET + BOOTP_SNAME_LEN)//108
#define BOOTP_FILE_LEN              128
#define BOOTP_MAGIC_COOKIE_OFFSET   (BOOTP_FILE_OFFSET + BOOTP_FILE_LEN)//236
#define BOOTP_MAGIC_COOKIE_LEN      4
#define BOOTP_OPTIONS_OFFSET        (BOOTP_MAGIC_COOKIE_OFFSET + BOOTP_MAGIC_COOKIE_LEN) //240   //start of the dhcp options

#define BOOTP_FRAME_TOTAL_LEN       BOOTP_OPTIONS_OFFSET

/*FIXME implemented the minimum required options, this may be sufficient*/
#define DHCP_FRAME_START_INDEX      (BOOTP_FRAME_START_INDEX + BOOTP_OPTIONS_OFFSET)
#define DHCP_MTYPE_OFFSET           0
#define DHCP_MTYPE_LEN              3
#define DHCP_CID_OFFSET             (DHCP_MTYPE_OFFSET + DHCP_MTYPE_LEN)
#define DHCP_CID_LEN                9

#define DHCP_FIXED_TOTAL_LEN        (DHCP_CID_OFFSET + DHCP_CID_LEN)

/*inclusion of following options depend on message type*/
#define DHCP_VAR_START_INDEX        (DHCP_FRAME_START_INDEX + DHCP_FIXED_TOTAL_LEN)

/*Discover:*/
#define DHCP_PARAM_OFFSET           0
#define DHCP_PARAM_LEN              7
#define DHCP_END_DISC_OFFSET        (DHCP_PARAM_OFFSET + DHCP_PARAM_LEN) 
#define DHCP_END_DISC_LEN           1

#define DHCP_DISC_VAR_TOTAL_LEN     (DHCP_END_DISC_OFFSET + DHCP_END_DISC_LEN)

/*Request:*/
#define DHCP_SVRID_OFFSET           0
#define DHCP_SVRID_LEN              4
#define DHCP_END_REQ_OFFSET         (DHCP_SVRID_OFFSET + DHCP_SVRID_LEN)
#define DHCP_END_REQ_LEN            1

#define DHCP_REQ_VAR_TOTAL_LEN      (DHCP_END_REQ_OFFSET + DHCP_END_REQ_LEN)

/*FRAME HEADER LENGTHS*/
#define ETH_FRAME_HDR_LEN           (IP_FRAME_START_INDEX - ETH_FRAME_START_INDEX)
#define IP_FRAME_HDR_LEN            (UDP_FRAME_START_INDEX - IP_FRAME_START_INDEX)

#define MASK16 0xFFFF

static uint16_t dhcp_checksum(uint8_t *data, uint16_t index_start, uint16_t index_end);


//typedef enum {DHCPDISCOVER=1, DHCPOFFER, DHCPREQUEST, 
//                DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE, DHCPINFORM} MSG_TYPE;

static uint16_t dhcp_checksum(uint8_t *data, uint16_t index_start, uint16_t index_end){
    int i, len;
    uint16_t tmp=0;
    uint32_t chksm=0, carry=0;

    if (index_start > index_end){     //range indexing error
#define DEBUG
#ifdef DEBUG
        fprintf(stderr, "checksum calulation: buffer range error\n");
#endif
        return -1;
    }

    len = index_end - index_start + 1;

//printf("len=%d ; start=%d ; end=%d\n", len, index_start, index_end);

    for (i=index_start; i<(index_start+len); i+=2){
        tmp = (uint16_t) data[i];
        tmp = tmp << 8;
        if (i == (len-1)){     //last iteration - only valid for (len%2 == 1)
            tmp = tmp + 0;
        }
        else{
            tmp = tmp + (uint16_t) data[i+1];
        }

#ifdef DEBUG
        fprintf(stderr, "tmp=%5x\t",tmp);
#endif
        //get 1's complement of data
        tmp = ~tmp;
#ifdef DEBUG
        fprintf(stderr, "~tmp=%5x\t",tmp);
#endif
        //aggregate -> doing 16bit arithmetic within 32bit words to preserve overflow
        chksm = chksm + tmp;
#ifdef DEBUG
        fprintf(stderr, "chksm before carry=%5x\t",chksm);
#endif
        //get overflow
        carry = chksm >> 16;
#ifdef DEBUG
        fprintf(stderr, "carry=%5x\t",carry);
#endif
        //add to checksum
        chksm = (MASK16 & chksm) + carry;
#ifdef DEBUG
        fprintf(stderr, "chksm after carry=%5x\n",chksm);
#endif
#undef DEBUG

    }

    return chksm;
}



int dhcp_msg(struct getap_state *gs, MSG_TYPE mt){
    uint16_t len=0, chksm=0, sec=0;
    uint8_t tmp_src_ip[4] = {0};
    uint8_t tmp_dst_ip[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t broadcast_const[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    /*zero the buffer*/
    memset(gs->s_dhcp_buffer, 0, GETAP_DHCP_BUFFER_SIZE);
    
    /*build up the dhcp packet*/

    /*ethernet frame stuff*/
    memcpy(gs->s_dhcp_buffer + ETH_DST_OFFSET, broadcast_const, 6);
    memcpy(gs->s_dhcp_buffer + ETH_SRC_OFFSET, gs->s_mac_binary, 6);

    /*frame type is IP*/
    gs->s_dhcp_buffer[ETH_FRAME_TYPE_OFFSET] = 0x08;
    gs->s_dhcp_buffer[ETH_FRAME_TYPE_OFFSET + 1] = 0x00;

    /*ip frame stuff*/
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_V_HIL_OFFSET] = 0x45;
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_TOS_OFFSET] = 0x00;
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_ID_OFFSET] = 0x00;
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_ID_OFFSET + 1] = 0x00;

    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_FLAG_FRAG_OFFSET] = 0x00;
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_FLAG_FRAG_OFFSET + 1] = 0x00;

    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_TTL_OFFSET] = 0x40;
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_PROT_OFFSET] = 0x11;

    //enter zeros for checksum calculation
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET] = 0x00;
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET + 1] = 0x00;

    memcpy(gs->s_dhcp_buffer + IP_FRAME_START_INDEX + IP_DST_OFFSET, tmp_dst_ip, 4);
    memcpy(gs->s_dhcp_buffer + IP_FRAME_START_INDEX + IP_SRC_OFFSET, tmp_src_ip, 4);

        /*TODO ip length and checksum to be calculated later*/

    /*udp frame stuff*/

    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_SRC_PORT_OFFSET] = 0x00;
    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_SRC_PORT_OFFSET + 1] = 0x44;
    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_DST_PORT_OFFSET] = 0x00;
    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_DST_PORT_OFFSET + 1] = 0x43;

    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_CHKSM_OFFSET] = 0x00;
    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_CHKSM_OFFSET + 1] = 0x00;

        /*TODO length to be calculated later, udp cahecksum not strictly required (make zero)*/


    /*bootp stuff*/
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_OPTYPE_OFFSET] = 0x01;
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_HWTYPE_OFFSET] = 0x01;
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_HWLEN_OFFSET] = 0x06;
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_HOPS_OFFSET] = 0x00;

    if (mt == DHCPDISCOVER){
        srand(time(NULL));
        gs->s_dhcp_xid = (uint32_t)rand();
        gs->s_dhcp_sec_start = time(NULL);
    }

    /*generally tried to work on byte level to avoid endianness issues*/
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET    ]= (uint8_t) ((gs->s_dhcp_xid >> 24) & 0xFF);
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET + 1]= (uint8_t) ((gs->s_dhcp_xid >> 16) & 0xFF);
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET + 2]= (uint8_t) ((gs->s_dhcp_xid >>  8) & 0xFF);
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET + 3]= (uint8_t) ((gs->s_dhcp_xid      ) & 0xFF);

    sec = time(NULL) - gs->s_dhcp_sec_start;
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_SEC_OFFSET] = (uint8_t) (sec >> 8);
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_SEC_OFFSET] = (uint8_t) (sec & 0xFF);

    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_FLAGS_OFFSET, 0x00, 2);

    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_CIPADDR_OFFSET, 0x00, 4);
    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_YIPADDR_OFFSET, 0x00, 4);
    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_SIPADDR_OFFSET, 0x00, 4);
    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_GIPADDR_OFFSET, 0x00, 4);

    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_CHWADDR_OFFSET, 0x00, 16);
    memcpy(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_CHWADDR_OFFSET, gs->s_mac_binary, 6);

    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_SNAME_OFFSET, '\0', 64);
    memset(gs->s_dhcp_buffer + BOOTP_FRAME_START_INDEX + BOOTP_FILE_OFFSET, '\0', 128);

    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET] = 0x63;
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET + 1] = 0x82;
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET + 2] = 0x53;
    gs->s_dhcp_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET + 3] = 0x63;

    /*dhcp stuff -> dhcp is implemeted as an extension to bootp through bootp options*/
    gs->s_dhcp_buffer[DHCP_FRAME_START_INDEX + DHCP_MTYPE_OFFSET] = 53;
    gs->s_dhcp_buffer[DHCP_FRAME_START_INDEX + DHCP_MTYPE_OFFSET + 1] = 1;
    gs->s_dhcp_buffer[DHCP_FRAME_START_INDEX + DHCP_MTYPE_OFFSET + 2] = (uint8_t) mt;

    gs->s_dhcp_buffer[DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET] = 61;
    gs->s_dhcp_buffer[DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET + 1] = 7;
    gs->s_dhcp_buffer[DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET + 2] = 1;
    memcpy(gs->s_dhcp_buffer + DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET + 3 , gs->s_mac_binary, 6);

    switch(mt){
        case DHCPDISCOVER:
            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET] = 55;
            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 1] = 5;
            /*request the following parameters*/
            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 2] = 1;  //subnet mask
            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 3] = 3;  //router
            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 4] = 6;  //dname svr
            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 5] = 12; //host name
            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 6] = 15; //domain name

            gs->s_dhcp_buffer[DHCP_VAR_START_INDEX + DHCP_END_DISC_OFFSET] = 0xFF;
            len = DHCP_DISC_VAR_TOTAL_LEN;
            break;

//        case DHCPREQUEST:
//            len = DHCP_REQ_VAR_TOTAL_LEN;
//            break;

        default:
#ifdef DEBUG
            fprintf(stderr, "dhcp message type '%d' not implemented\n", mt);
#endif
            return -1;
    }

    /*calculate packet lengths*/
    //udp_frame_len 
    len =  len + UDP_FRAME_TOTAL_LEN + BOOTP_FRAME_TOTAL_LEN + DHCP_FIXED_TOTAL_LEN;
    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_ULEN_OFFSET] = (uint8_t) (len >> 8);
    gs->s_dhcp_buffer[UDP_FRAME_START_INDEX + UDP_ULEN_OFFSET + 1] = (uint8_t) (len & 0xFF);

    //ip_frame_len
    len = len + IP_FRAME_TOTAL_LEN;
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_TLEN_OFFSET] = (uint8_t) (len >> 8);
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_TLEN_OFFSET + 1] = (uint8_t) (len & 0xFF);

    /*calculate checksums - ip mandatory, udp optional*/
//    chksm = dhcp_checksum(gs->s_dhcp_buffer, IP_FRAME_START_INDEX, GETAP_DHCP_BUFFER_SIZE - 1);
    chksm = dhcp_checksum(gs->s_dhcp_buffer, IP_FRAME_START_INDEX, UDP_FRAME_START_INDEX - 1);
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET] = (uint8_t) (chksm >> 8);
    gs->s_dhcp_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET + 1] = (uint8_t) (chksm & 0xFF);

    return 0;
}

#if 0
int tap_dhcp_cmd(struct katcp_dispatch *d, int argc){

    char *name;
    struct katcp_arb *a;
    struct getap_state *gs;
    int ret, i;

    if(argc <= 1){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "need a register name");
        return KATCP_RESULT_INVALID;
    }

    name = arg_string_katcp(d, 1);
    if(name == NULL){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "internal failure while acquiring parameters");
        return KATCP_RESULT_FAIL;
    }

    a = find_arb_katcp(d, name);
    if(a == NULL){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to locate %s", name);
        return KATCP_RESULT_FAIL;
    }

    gs = data_arb_katcp(d, a);
    if(gs == NULL){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "no user state found for %s", name);
        return KATCP_RESULT_FAIL;
    }


    ret = dhcp_msg(gs, DHCPDISCOVER);
    if (ret){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to generate dhcp message");
        return KATCP_RESULT_FAIL;
    }


//#ifdef DEBUG
    for (i=0; i<GETAP_DHCP_BUFFER_SIZE; i++){
        fprintf(stdout, "%#04x ", gs->s_dhcp_buffer[i]);
    }
    fprintf(stdout, "\n");
    //write(STDOUT_FILENO, gs->s_dhcp_buffer, GETAP_DHCP_BUFFER_SIZE);
//#endif
        return KATCP_RESULT_OK;
}

#endif
