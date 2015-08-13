#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <katcp.h>
#include <katcl.h>
#include <avltree.h>

#include "tcpborphserver3.h"
#include "tapper.h"
#include "tg.h"

#define POLL_INTERVAL         10  /* polling interval, in msecs, how often we look at register */
#define CACHE_DIVISOR          4  /* 256 / div - longest initial delay */

#define FRESH_VALID        50000 /* length of time to cache a valid reply - units are poll interval, approx */

#define ANNOUNCE_INITIAL     100 /* how often we announce ourselves initially */
#define ANNOUNCE_FINAL      1600 /* rate to which we decay */
#define ANNOUNCE_STEP        100 /* amount by which we increment */

#define SMALL_DELAY           10 /* wait this long before announcing ourselves, after arp reply */

#define SPAM_INITIAL           5 /* how often we spam an address initially */
#define SPAM_FINAL        160000 /* rate at which we end up */
#define SPAM_STEP            700 /* amount by which we increment */

#if 0
#define FRESH_ANNOUNCE_FINAL  8000 /* interval when we announce ourselves - good idea to be shorter than others */
#define FRESH_ANNOUNCE_INITIAL  13 /* initial spamming interval, can not be smaller than 2 */
#define FRESH_ANNOUNCE_LINEAR   70 /* value before which we are linear - not quadratic */

#define ANNOUNCE_RATIO           4 /* own announcements happen more frequently than queries */
#endif

#define COPRIME_A         5 /* initial arp spamming offset as multiple of instance number, units poll interval */
#define COPRIME_B        23 /* some other offset ... */
#define COPRIME_C       101 /* offset to make requests not sequential ... */

#define RECEIVE_BURST      8 /* read at most N frames per polling interval */

#define GO_DEFAULT_PORT 7148

#define GO_MAC          0x00
#define GO_GATEWAY      0x0c
#define GO_ADDRESS      0x10

#define GO_MCADDR       0x30 /*mcast ip*/
#define GO_MCMASK       0x34 /*mcast count ff.ff.ff.f7 to encode ip base +8 addresses
                               or          ff.ff.ff.fb to encode ip base +4 addresses*/
#define GO_BUFFER_SIZES 0x18
#define GO_EN_RST_PORT  0x20

#define GO_LINK_STATUS  0x24
#define GO_SUBNET       0x38

#define GO_TXBUFFER   0x1000
#define GO_RXBUFFER   0x2000

#define GO_ARPTABLE   0x3000

#define MIN_FRAME         64

#define MAX_SUBNET        24

#define IP_SIZE            4

#define NAME_BUFFER       64
#define CMD_BUFFER      1024

#define FRAME_TYPE1       12
#define FRAME_TYPE2       13

#define FRAME_DST          0
#define FRAME_SRC          6

#define ARP_OP1            6
#define ARP_OP2            7

#define ARP_SHA_BASE       8
#define ARP_SIP_BASE      14
#define ARP_THA_BASE      18
#define ARP_TIP_BASE      24

#define SIZE_FRAME_HEADER 14

#define IP_DEST1          16
#define IP_DEST2          17
#define IP_DEST3          18
#define IP_DEST4          19

#define RUNT_LENGTH       20 /* want a basic ip packet */

#define GS_MAGIC  0x490301fc

#define ARP_MODE_LOOP     -1 /* continuous */
#define ARP_MODE_OFF       0 /* off */
#define ARP_MODE_SINGLE    1 /* once */
#define ARP_MODE_DEFAULT   3 /* three sweeps */


/*********************dhcp macro definitions*********************/
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
//#define DHCP_PARAM_OFFSET           0
//#define DHCP_PARAM_LEN              7
//#define DHCP_END_DISC_OFFSET        (DHCP_PARAM_OFFSET + DHCP_PARAM_LEN) 
#define DHCP_END_DISC_OFFSET         0
#define DHCP_END_DISC_LEN           1

#define DHCP_DISC_VAR_TOTAL_LEN     (DHCP_END_DISC_OFFSET + DHCP_END_DISC_LEN)

/*Request:*/
#define DHCP_SVRID_OFFSET           0
#define DHCP_SVRID_LEN              6
#define DHCP_PARAM_OFFSET           (DHCP_SVRID_OFFSET + DHCP_SVRID_LEN)
#define DHCP_PARAM_LEN              7
#define DHCP_REQIP_OFFSET           (DHCP_PARAM_OFFSET + DHCP_PARAM_LEN)
#define DHCP_REQIP_LEN              6
#define DHCP_END_REQ_OFFSET         (DHCP_REQIP_OFFSET + DHCP_REQIP_LEN)
#define DHCP_END_REQ_LEN            1

#define DHCP_REQ_VAR_TOTAL_LEN      (DHCP_END_REQ_OFFSET + DHCP_END_REQ_LEN)

/*FRAME HEADER LENGTHS*/
#define ETH_FRAME_HDR_LEN           (IP_FRAME_START_INDEX - ETH_FRAME_START_INDEX)
#define IP_FRAME_HDR_LEN            (UDP_FRAME_START_INDEX - IP_FRAME_START_INDEX)

#define MASK16 0xFFFF

/*********************dhcp macro definitions end here*********************/


static const uint8_t arp_const[] = { 0, 1, 8, 0, 6, 4, 0 }; /* disgusting */
static const uint8_t broadcast_const[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/************************************************************************/

static int write_mac_fpga(struct getap_state *gs, unsigned int offset, const uint8_t *mac);
static int write_frame_fpga(struct getap_state *gs, unsigned char *data, unsigned int len);


typedef enum {DHCPDISCOVER=1, DHCPOFFER, DHCPREQUEST,
            DHCPDECLINE, DHCPACK, DHCPNAK, DHCPRELEASE, DHCPINFORM} DHCP_MSG_TYPE;

static uint16_t dhcp_checksum(uint8_t *data, uint16_t index_start, uint16_t index_end);
static int dhcp_msg(struct getap_state *gs, DHCP_MSG_TYPE mt);
static int validate_dhcp_reply(struct getap_state *gs);
static DHCP_MSG_TYPE process_dhcp(struct getap_state *gs);
static int dhcp_statemachine(struct getap_state *gs);
static int dhcp_configure_if(struct getap_state *gs);
static int dhcp_convert_netmask(struct getap_state *gs);

/************************************************************************/

#ifdef DEBUG
static void sane_gs(struct getap_state *gs)
{
  if(gs == NULL){
    fprintf(stderr, "tap: invalid handle\n");
    abort();
  }
  if(gs->s_magic != GS_MAGIC){
    fprintf(stderr, "tap: bad magic 0x%x\n", gs->s_magic);
    abort();
  }
}
#else
#define sane_gs(d)
#endif

/* mac parsing and generation *******************************************/

void generate_text_mac(char *text, unsigned int index)
{
  struct utsname un;
  char tmp[GETAP_MAC_SIZE];
  pid_t pid;
  int i, j;

  memset(tmp, 0, GETAP_MAC_SIZE);

  /* generate the mac address somehow */
  tmp[0] = 0x02; 
  tmp[1] = 0x40 - index;
  if((uname(&un) >= 0) && un.nodename){
    strncpy(tmp + 2, un.nodename, GETAP_MAC_SIZE - 2);
  } else {
    pid = getpid();
    memcpy(tmp + 2, &pid, GETAP_MAC_SIZE - 2);
  }

  snprintf(text, GETAP_MAC_BUFFER, "%02x", tmp[0]);
  j = 2;

  for(i = 1; i < GETAP_MAC_SIZE; i++){
    snprintf(text + j, GETAP_MAC_BUFFER - j, ":%02x", tmp[i]);
    j += 3;
  }
}

int text_to_mac(uint8_t *binary, const char *text)
{
  int i;
  unsigned int v;
  char *end;
  const char *ptr;

  ptr = text;
  for(i = 0; i < 6; i++){
    v = strtoul(ptr, &end, 16);
    if(v >= 256){
      return -1;
    }
    binary[i] = v;
    if(i < 5){
      if(*end != ':'){
        return -1;
      }
      ptr = end + 1;
    }
  }

#ifdef DEBUG
  fprintf(stderr, "text_to_mac: in=%s, out=", text);
  for(i = 0; i < 6; i++){
    fprintf(stderr, "%02x ", binary[i]);
  }
  fprintf(stderr, "\n");
#endif

  return 0;
}

static unsigned int compute_spam_rate(struct getap_state *gs, unsigned int index)
{
  /* WARNING: better make sure this array is actually the correct size */
  unsigned int third, extra, value;

  if(gs->s_spam_period[GETAP_PERIOD_CURRENT] >= gs->s_spam_period[GETAP_PERIOD_STOP]){
    gs->s_spam_period[GETAP_PERIOD_CURRENT] = gs->s_spam_period[GETAP_PERIOD_STOP];
  }

  third = (gs->s_spam_period[GETAP_PERIOD_CURRENT] / 3);
  extra = (third / gs->s_table_size) * index;

  if(third <= 0){
    third = 1;
  }

#if 0
  value = (2 + (((index + array[GETAP_PERIOD_CURRENT]) * COPRIME_C) % 3) ? 1 : 0) * third;
#endif

  value = (2 * third) + ((((index * COPRIME_A) + (gs->s_iteration * COPRIME_B) + (gs->s_self * gs->s_spam_period[GETAP_PERIOD_CURRENT])) % 3) ? extra : third);
  
  return value;
}

static void fixup_spam_rate(struct getap_state *gs)
{
  gs->s_spam_period[GETAP_PERIOD_CURRENT] = gs->s_spam_period[GETAP_PERIOD_CURRENT] + gs->s_spam_period[GETAP_PERIOD_INCREMENT];

  if(gs->s_spam_period[GETAP_PERIOD_CURRENT] > gs->s_spam_period[GETAP_PERIOD_STOP]){
    gs->s_spam_period[GETAP_PERIOD_CURRENT] =  gs->s_spam_period[GETAP_PERIOD_STOP];
  }
}

static unsigned int compute_announce_rate(struct getap_state *gs)
{
  /* WARNING: better make sure this array is actually the correct size */

  if(gs->s_announce_period[GETAP_PERIOD_CURRENT] >= gs->s_announce_period[GETAP_PERIOD_STOP]){
    return gs->s_announce_period[GETAP_PERIOD_STOP];
  }

  gs->s_announce_period[GETAP_PERIOD_CURRENT] += gs->s_announce_period[GETAP_PERIOD_INCREMENT];

  return gs->s_announce_period[GETAP_PERIOD_CURRENT];
}

/* arp related functions  ***********************************************/

int set_entry_arp(struct getap_state *gs, unsigned int index, const uint8_t *mac, unsigned int fresh)
{

#ifdef DEBUG
  fprintf(stderr, "arp: entering at index %u\n", index);
#endif

  if(index > gs->s_table_size){
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_WARN, NULL, "logic failure: attempting to set entry %u/%d", index, gs->s_table_size);
    return -1;
  }

  memcpy(gs->s_arp_table[index], mac, 6);
  gs->s_arp_fresh[index] = gs->s_iteration + fresh;

  return write_mac_fpga(gs, GO_ARPTABLE + (8 * index), mac);
}

void glean_arp(struct getap_state *gs, uint8_t *mac, uint8_t *ip)
{
  uint32_t v;
  unsigned int index;

  memcpy(&v, ip, 4);

#ifdef DEBUG
  fprintf(stderr, "glean: considering ip %08x", v);
#endif

  if(v == 0){
    return;
  }

  if((v & gs->s_mask_binary) != gs->s_network_binary){
#ifdef DEBUG
    fprintf(stderr, "glean: not my network 0x%08x != 0x%08x\n", v & gs->s_mask_binary, gs->s_network_binary);
#endif
    return;
  }

  if((v ^ gs->s_network_binary) == ~(gs->s_mask_binary)){
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_ERROR, NULL, "odd arp packet for subnet broadcast %08x in subnet %08x", v, gs->s_network_binary);
    return;
  }

  index = ntohl(v & ~(gs->s_mask_binary));
  if((index == 0) || (index >= gs->s_table_size)){
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_ERROR, NULL, "logic problem for ip %08x yielding index %u with a subnet of %u-2 stations", v, index, gs->s_table_size);
    return;
  }

#ifdef DEBUG
  fprintf(stderr, "glean: adding entry %d\n", index);
#endif

  set_entry_arp(gs, index, mac, gs->s_valid_period + (gs->s_table_size - ((index > gs->s_self) ? (index - gs->s_self) : (gs->s_self - index))));
}

void announce_arp(struct getap_state *gs)
{
  uint32_t subnet;
  int result;

  subnet = (~(gs->s_mask_binary)) | gs->s_address_binary;

  memcpy(gs->s_arp_buffer + FRAME_DST, broadcast_const, 6);
  memcpy(gs->s_arp_buffer + FRAME_SRC, gs->s_mac_binary, 6);

  gs->s_arp_buffer[FRAME_TYPE1] = 0x08;
  gs->s_arp_buffer[FRAME_TYPE2] = 0x06;

  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER, arp_const, 7);

  gs->s_arp_buffer[SIZE_FRAME_HEADER + ARP_OP2] = 2;

  /* spam the subnet */
  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_TIP_BASE, &subnet, 4);
  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_THA_BASE, broadcast_const, 6);

  /* write in our own sending information */
  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_SIP_BASE, &(gs->s_address_binary), 4);
  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_SHA_BASE, gs->s_mac_binary, 6);

#ifdef DEBUG
  fprintf(stderr, "arp: sending arp announce\n");
#endif

  gs->s_arp_len = 42;

#ifdef DEBUG
  if((gs->s_arp_len + 4) > GETAP_ARP_FRAME){ /* test should be more sophisticated ... */
    fprintf(stderr, "arp: critical problem: arp packet of %u bytes exceeds buffer\n", gs->s_arp_len);
  }
#endif

  result = write_frame_fpga(gs, gs->s_arp_buffer, gs->s_arp_len);
  if(result != 0){
    gs->s_arp_len = 0;
    if(result > 0){
      gs->s_tx_arp++;
    } else {
      gs->s_tx_error++;
    }
  }

#if 0
  if(gs->s_period < FRESH_ANNOUNCE_FINAL){
    if(gs->s_period < FRESH_ANNOUNCE_LINEAR){
      gs->s_period = gs->s_period + 1;
    } else {
      gs->s_period = gs->s_period * 2;
    }
  } else {
    gs->s_period = FRESH_ANNOUNCE_FINAL;
  }
#endif

  gs->s_arp_fresh[gs->s_self] = gs->s_iteration + compute_announce_rate(gs);
}

static void request_arp(struct getap_state *gs, int index)
{
  uint32_t host;
#if 0
  unsigned int extra, pos, delta, reference, mine;
#endif
  int result;

  if(gs->s_self == index){
    return;
  }

  host = htonl(index) | (gs->s_mask_binary & gs->s_address_binary);

  memcpy(gs->s_arp_buffer + FRAME_DST, broadcast_const, 6);
  memcpy(gs->s_arp_buffer + FRAME_SRC, gs->s_mac_binary, 6);

  gs->s_arp_buffer[FRAME_TYPE1] = 0x08;
  gs->s_arp_buffer[FRAME_TYPE2] = 0x06;

  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER, arp_const, 7);

  gs->s_arp_buffer[SIZE_FRAME_HEADER + ARP_OP2] = 1;

  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_TIP_BASE, &host, 4);
  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_THA_BASE, broadcast_const, 6);

  /* write in our own sending information */
  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_SIP_BASE, &(gs->s_address_binary), 4);
  memcpy(gs->s_arp_buffer + SIZE_FRAME_HEADER + ARP_SHA_BASE, gs->s_mac_binary, 6);

#ifdef DEBUG
  fprintf(stderr, "arp: sending arp request for index %d (host=0x%08x)\n", index, host);
#endif

#if 0
  /* pick an entry at random ... */
  pos = (gs->s_iteration + index) % (GETAP_ARP_CACHE - 2) + 1;
  reference = gs->s_arp_fresh[pos];

  mine = gs->s_iteration + (gs->s_period * ANNOUNCE_RATIO);
  if(mine > reference){
    delta = mine - reference;
    /* try to get away from random entry ... */
    if(delta < gs->s_period){

      extra = (COPRIME_B * ((index % COPRIME_A) + 1));
      /* by some weird amount */
      if(extra > gs->s_period){
        extra = gs->s_period;
      }
      mine += extra;
    }
  }
  gs->s_arp_fresh[index] = mine;
#endif

  gs->s_arp_fresh[index] = gs->s_iteration + compute_spam_rate(gs, index);

  gs->s_arp_len = 42;
#ifdef DEBUG
  if((gs->s_arp_len + 4) > GETAP_ARP_FRAME){ /* test should be more sophisticated ... */
    fprintf(stderr, "arp: critical problem: arp packet of %u bytes exceeds buffer\n", gs->s_arp_len);
  }
#endif

  result = write_frame_fpga(gs, gs->s_arp_buffer, gs->s_arp_len);
  if(result != 0){
    gs->s_arp_len = 0;
    if(result > 0){
      gs->s_tx_arp++;
    } else {
      gs->s_tx_error++;
    }
  }
}

int reply_arp(struct getap_state *gs)
{
  int result;

  /* TODO - check that we are in the correct subnet before answering */

  /* WARNING: attempt to get away without using the arp buffer, just turn the rx buffer around */
  memcpy(gs->s_rxb + FRAME_DST, gs->s_rxb + FRAME_SRC, 6);
  memcpy(gs->s_rxb + FRAME_SRC, gs->s_mac_binary, 6);

  gs->s_rxb[SIZE_FRAME_HEADER + ARP_OP2] = 2;

  /* make sender of receive the target of transmit*/
  memcpy(gs->s_rxb + SIZE_FRAME_HEADER + ARP_THA_BASE, gs->s_rxb + SIZE_FRAME_HEADER + ARP_SHA_BASE, 10); 

  /* write in our own sending information */
  memcpy(gs->s_rxb + SIZE_FRAME_HEADER + ARP_SIP_BASE, &(gs->s_address_binary), 4);
  memcpy(gs->s_rxb + SIZE_FRAME_HEADER + ARP_SHA_BASE, gs->s_mac_binary, 6);

#ifdef DEBUG
  fprintf(stderr, "arp: sending arp reply\n");
#endif

  result = write_frame_fpga(gs, gs->s_rxb, 42);
  if(result == 0){
    /* WARNING: in case of write failure, clobber arp buffer to save reply. The buffer could contain something else (probably generated by spam_arp), but we assume the current one is more important. In any event, if writes fail on the 10Gbe interface we are already in trouble */
    memcpy(gs->s_arp_buffer, gs->s_rxb, 42);
    gs->s_arp_len = 42;
  } else {
    if(result > 0){
      gs->s_tx_arp++;
    } else {
      gs->s_tx_error++;
    }
  }

  /* WARNING: heuristic: also announce ourselves soon, on the basis that others might also want to know about us */
  gs->s_arp_fresh[gs->s_self] = gs->s_iteration + SMALL_DELAY;

  return result;
}

int process_arp(struct getap_state *gs)
{
#ifdef DEBUG
  fprintf(stderr, "arp: got arp packet\n");
#endif

  if(memcmp(arp_const, gs->s_rxb + SIZE_FRAME_HEADER, 7)){
    fprintf(stderr, "arp: unknown or malformed arp packet\n");
    return -1;
  }

  switch(gs->s_rxb[SIZE_FRAME_HEADER + ARP_OP2]){
    case 2 : /* reply */
#ifdef DEBUG
      fprintf(stderr, "arp: saw reply\n");
#endif
      glean_arp(gs, gs->s_rxb + SIZE_FRAME_HEADER + ARP_SHA_BASE, gs->s_rxb + SIZE_FRAME_HEADER + ARP_SIP_BASE);
      return 1;

    case 1 : /* request */
#ifdef DEBUG
      fprintf(stderr, "arp: saw request\n");
#endif
      if(!memcmp(gs->s_rxb + SIZE_FRAME_HEADER + ARP_TIP_BASE, &(gs->s_address_binary), 4)){
#ifdef DEBUG
        fprintf(stderr, "arp: somebody is looking for me\n");
#endif
        return reply_arp(gs);
      } else {
        gs->s_x_glean++;
        glean_arp(gs, gs->s_rxb + SIZE_FRAME_HEADER + ARP_SHA_BASE, gs->s_rxb + SIZE_FRAME_HEADER + ARP_SIP_BASE);
        return 1;
      }
    default :
      fprintf(stderr, "arp: unhandled arp message %x\n", gs->s_rxb[SIZE_FRAME_HEADER + ARP_OP2]);
      return -1;
  }
}

void spam_arp(struct getap_state *gs)
{
#if 0
  unsigned int i;
  uint32_t update;
#endif
  unsigned int consider;

  /* unfortunate, but the gateware needs to know other systems and can't wait, so we have to work things out in advance */

  if(gs->s_arp_len > 0){
    /* already stuff in arp buffer not flushed, wait ... */
    return;
  }

  if(gs->s_table_size > GETAP_ARP_CACHE){
#ifdef DEBUG
    fprintf(stderr, "major logic issue, table size=%d exceeds space\n", gs->s_table_size);
#endif
    gs->s_table_size = GETAP_ARP_CACHE;
  }


  while(gs->s_index < (gs->s_table_size - 1)){

    consider = gs->s_arp_fresh[gs->s_index];

/* if integers never wrapped, then we could have done consider <= gs->s_iteration, but ... */

    if(((gs->s_iteration >= consider) ? (gs->s_iteration - consider) : (UINT32_MAX - (consider - gs->s_iteration))) < (2 * GETAP_ARP_CACHE)){
      if(gs->s_index == gs->s_self){
        announce_arp(gs);
      } else {
        request_arp(gs, gs->s_index);
      }
      gs->s_index++;
      gs->s_iteration++;
      return;
    }
    gs->s_index++;
  }

  fixup_spam_rate(gs);
  if(gs->s_arp_mode > 0){
    gs->s_arp_mode--;
  }

  gs->s_index = 1;
  gs->s_iteration++;

#if 0
  for(i = 1; i < 254; i++){
    if(gs->s_arp_fresh[i] => gs->s_iteration){
      if(update){ /* defer */
        gs->s_arp_fresh[i] += update;
      } else {
        if(i == gs->s_self){
          announce_arp(gs);
        } else {
          request_arp(gs, i);
        }
      }
      update++;
    }
  }

  gs->s_iteration++;
#endif

}

/* status from gateware *************************************************/

static uint32_t link_status_fpga(struct getap_state *gs)
{
  uint32_t value;
  void *base;

  base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base;

  value = *((uint32_t *)(base + GO_LINK_STATUS));

  return value;
}

/* transmit to gateware *************************************************/

static int write_mac_fpga(struct getap_state *gs, unsigned int offset, const uint8_t *mac)
{
  uint32_t value;
  void *base;

#if 0
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_DEBUG, NULL, "writing mac %x:%x:%x:%x:%x:%x to offset 0x%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], offset);
#endif

  base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base;

  value = (   0x0         & 0xff000000) | 
          (   0x0         & 0xff0000) |
          ((mac[0] <<  8) & 0xff00) | 
           (mac[1]        & 0xff);
  *((uint32_t *)(base + offset)) = value;


  value = ((mac[2] << 24) & 0xff000000) | 
          ((mac[3] << 16) & 0xff0000) |
          ((mac[4] <<  8) & 0xff00) |
           (mac[5]        & 0xff);
  *((uint32_t *)(base + offset + 4)) = value;

  return 0;
}

#if 0
int write_mac_fpga(struct getap_state *gs, unsigned int offset, const uint8_t *mac)
{
  uint32_t v[2];
  struct katcp_dispatch *d;
  void *base;

  d = gs->s_dispatch;
  base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base + offset;

  v[0] = (   0x0         & 0xff000000) | 
         (   0x0         & 0xff0000) |
         ((mac[0] <<  8) & 0xff00) | 
          (mac[1]        & 0xff);
  v[1] = ((mac[2] << 24) & 0xff000000) | 
         ((mac[3] << 16) & 0xff0000) |
         ((mac[4] <<  8) & 0xff00) |
          (mac[5]        & 0xff);

  memcpy(base, v, 8);

  return 0;
}
#endif

/* transmit to gateware *************************************************/

#define CRCPOLY_LE 0xedb88320

static uint32_t crc32_le(uint32_t crc, unsigned char *p, unsigned int len)
{
  int i;
  while (len--){
    crc ^= *p++;
    for (i = 0; i < 8; i++){
      crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
    }
  }
  return crc;
}

static int write_frame_fpga(struct getap_state *gs, unsigned char *data, unsigned int len)
{
  uint32_t buffer_sizes, tmp;
  unsigned int final, pad;
  struct katcp_dispatch *d;
  void *base;

  base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base;
#if DEBUG > 1
  fprintf(stderr, "txf: base address is %p + 0x%x\n", gs->s_raw_mode->r_map, gs->s_register->e_pos_base);
#endif
  d = gs->s_dispatch;

  if(len <= MIN_FRAME){
    if(len == 0){
      /* nothing to do */
      return 1;
    }
    pad = MIN_FRAME;
  } else {
    pad = len;
  }

  final = ((pad + 4 + 7) / 8) * 8;

  if(final > GETAP_MAX_FRAME){ /* subtract checksum */
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "frame request %u exeeds limit %u", final, GETAP_MAX_FRAME);
    return -1;
  }

  if(len < (final - 4)){
    memset(data + len, 0, (final - 4) - len);
  }

  buffer_sizes = *((uint32_t *)(base + GO_BUFFER_SIZES));
#ifdef DEBUG
  fprintf(stderr, "txf: previous value in tx word count is %d\n", buffer_sizes >> 16);
#endif

  if((buffer_sizes & 0xffff0000) > 0){
#ifdef __PPC__
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "tx queue still busy (%d words to send)", (buffer_sizes & 0xffff0000) >> 16);
    return 0;
#else
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "in test mode we ignore %d words previously queued", (buffer_sizes & 0xffff0000) >> 16);
#endif
  }

  tmp = crc32_le(0xffffffffUL, data, final - 4);

  data[final - 4] = ~(0xff & (tmp      ));
  data[final - 3] = ~(0xff & (tmp >>  8));
  data[final - 2] = ~(0xff & (tmp >> 16));
  data[final - 1] = ~(0xff & (tmp >> 24));

  memcpy(base + GO_TXBUFFER, data, final);

  buffer_sizes = (buffer_sizes & 0xffff) | (0xffff0000 & ((final / 8) << 16));

  *((uint32_t *)(base + GO_BUFFER_SIZES)) = buffer_sizes;

#ifdef DEBUG
  fprintf(stderr, "txf: wrote data to %p (bytes=%d, gateware register=0x%08x)\n", base + GO_TXBUFFER, final, buffer_sizes);
#endif

#ifdef DEBUG
  log_message_katcp(d, KATCP_LEVEL_DEBUG, NULL, "sent %u words to fpga from tap device %s", buffer_sizes >> 16, gs->s_tap_name);
#endif

  if(final < gs->s_tx_small){
    gs->s_tx_small = final;
  }
  if(final > gs->s_tx_big){
    gs->s_tx_big = final;
  }

  return 1;
}

static int transmit_frame_fpga(struct getap_state *gs)
{
  int result;

  result = write_frame_fpga(gs, gs->s_txb, gs->s_tx_len);
  if(result != 0){
    gs->s_tx_len = 0;
    if(result > 0){
      gs->s_tx_user++;
    } else {
      gs->s_tx_error++;
    }
  }

  return result;
}

 /*    
    An IP host group address is mapped to an Ethernet multicast address
    by placing the low-order 23-bits of the IP address into the low-order
    23 bits of the Ethernet multicast address 01-00-5E-00-00-00 (hex).
    Because there are 28 significant bits in an IP host group address,
    more than one host group address may map to the same Ethernet
    multicast address.
    i.e. take multicast address and it with 0x7FFFFF 
  */

int transmit_ip_fpga(struct getap_state *gs)
{
  uint8_t prefix[3] = { 0x01, 0x00, 0x5e };
  uint8_t *mac;
  unsigned int index;
  uint32_t value;

  memcpy(&value, &(gs->s_txb[SIZE_FRAME_HEADER + IP_DEST1]), 4);

#ifdef DEBUG
  fprintf(stderr, "ip->0x%08x ", value);
#endif

  if(value == htonl(0xffffffff)){ /* global broadcast */
    memcpy(gs->s_txb, broadcast_const, 6);
#ifdef DEBUG
    fprintf(stderr, "big broadcast ");
#endif

  } else if((value & (htonl(0xf0000000))) == htonl(0xe0000000)){ /* multicast */
    memcpy(gs->s_txb, prefix, 3);

    gs->s_txb[3] = 0x7f & gs->s_txb[SIZE_FRAME_HEADER + IP_DEST2];
    gs->s_txb[4] =        gs->s_txb[SIZE_FRAME_HEADER + IP_DEST3];
    gs->s_txb[5] =        gs->s_txb[SIZE_FRAME_HEADER + IP_DEST4];
#ifdef DEBUG
    fprintf(stderr, "multicast ");
#endif

  } else {
    if((value & gs->s_mask_binary) == (gs->s_network_binary)){ /* on same subnet */
      index = ntohl(value & (~(gs->s_mask_binary)));

#ifdef DEBUG
      fprintf(stderr, "direct link at %u ", index);
#endif

    } else if(gs->s_gateway_binary){ /* not in subnet */
      index = ntohl(gs->s_gateway_binary & (~(gs->s_mask_binary)));
#ifdef DEBUG
      fprintf(stderr, "via gateway 0x%08x (%u) ", gs->s_gateway_binary, index);
#endif
    } else {
#ifdef DEBUG
      fprintf(stderr, "no gateway set, dropping to floor\n");
#endif
      gs->s_tx_len = 0;
      gs->s_tx_error++;
      return -1;
    }

    if(index >= gs->s_table_size){
#ifdef DEBUG
      fprintf(stderr, "[unreasonable index %u] ", index);
#endif
      index = gs->s_table_size - 1;
    }
    mac = gs->s_arp_table[index];
    memcpy(gs->s_txb, mac, GETAP_MAC_SIZE);
  }

#ifdef DEBUG
  fprintf(stderr, "-> %x:%x:%x:%x:%x:%x\n", gs->s_txb[0], gs->s_txb[1], gs->s_txb[2], gs->s_txb[3], gs->s_txb[4], gs->s_txb[5]);
#endif
  
  return transmit_frame_fpga(gs);
}

/* receive from gateware ************************************************/
#define DEBUG 1
int receive_frame_fpga(struct getap_state *gs)
{
  /* 1 - useful data, 0 - false alarm, -1 problem */
  struct katcp_dispatch *d;
  uint32_t buffer_sizes;
  int len;
  void *base;
#ifdef DEBUG
  int i;
#endif

  base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base;
#if DEBUG > 1
  fprintf(stderr, "rxf: base address is %p + 0x%x\n", gs->s_raw_mode->r_map, gs->s_register->e_pos_base);
#endif
  d = gs->s_dispatch;

  if(gs->s_rx_len > 0){
    fprintf(stderr, "rxf: receive buffer (%u) not yet cleared\n", gs->s_rx_len);
    return -1;
  }

  buffer_sizes = *((uint32_t *)(base + GO_BUFFER_SIZES));
  len = (buffer_sizes & 0xffff) * 8;
  if(len <= 0){
#if DEBUG > 1
    fprintf(stderr, "rxf: nothing to read: register 0x%x\n", buffer_sizes);
#endif
    return 0;
  }

#ifdef DEBUG
  fprintf(stderr, "rxf: %d bytes to read\n", len);
#endif

  if((len <= SIZE_FRAME_HEADER) || (len > GETAP_MAX_FRAME)){
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "saw runt or oversized frame, len=%u bytes", len);
    return -1;
  }

  memcpy(gs->s_rxb, base + GO_RXBUFFER, len);

  gs->s_rx_len = len;

#ifdef DEBUG
  fprintf(stderr, "rxf: data:");
  for(i = 0; i < len; i++){
    fprintf(stderr, " %02x", gs->s_rxb[i]);
  }
  fprintf(stderr, "\n");
#endif

  /* WARNING: still unclear how this register ends up being read and writeable */
  buffer_sizes &= 0xffff0000;
  *((uint32_t *)(base + GO_BUFFER_SIZES)) = buffer_sizes;

  return 1;
}
#undef DEBUG
/* receive from kernel **************************************************/

int receive_ip_kernel(struct katcp_dispatch *d, struct getap_state *gs)
{
#ifdef DEBUG
  int i;
#endif
  int rr;

#ifdef DEBUG
  fprintf(stderr, "tap: got something to read from tap device\n");
#endif

  if(gs->s_tx_len > 0){
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "transmit buffer on device %s still in use", gs->s_tap_name);
    return 0;
  }

  rr = read(gs->s_tap_fd, gs->s_txb + SIZE_FRAME_HEADER, GETAP_MAX_FRAME - SIZE_FRAME_HEADER);
  switch(rr){
    case -1 :
      switch(errno){
        case EAGAIN : 
        case EINTR  :
          return 0;
        default :
          log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "read from tap device %s failed: %s", gs->s_tap_name, strerror(errno));
          return -1;
      }
    case  0 :
      log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "got unexpected end of file from tap device %s", gs->s_tap_name);
      return -1;
  }

  if(rr < RUNT_LENGTH){
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "read runt packet from tap deivce %s", gs->s_tap_name);
    return 0;
  }

#ifdef DEBUG
  fprintf(stderr, "rxt: tap rx=%d, data=", rr);
  for(i = 0; i < rr; i++){
    fprintf(stderr, " %02x", gs->s_txb[i]); 
  }
  fprintf(stderr, "\n");
#endif

  gs->s_tx_len = rr + SIZE_FRAME_HEADER;

  return 1;
}

/* send to kernel *******************************************************/

static void forget_receive(struct getap_state *gs)
{
  gs->s_rx_len = 0;
}

int transmit_ip_kernel(struct getap_state *gs)
{
  int wr;
  struct katcp_dispatch *d;

  d = gs->s_dispatch;

  if(gs->s_rx_len <= SIZE_FRAME_HEADER){
    if(gs->s_rx_len == 0){
      return 1;
    } else {
      forget_receive(gs);
      return -1;
    }
  }

  wr = write(gs->s_tap_fd, gs->s_rxb + SIZE_FRAME_HEADER, gs->s_rx_len - SIZE_FRAME_HEADER);
  if(wr < 0){
    switch(errno){
      case EINTR  :
      case EAGAIN :
        return 0;
      default :
        log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "write to tap device %s failed: %s", gs->s_tap_name, strerror(errno));
        /* WARNING: drops packet on floor, better than spamming logs */
        forget_receive(gs);
        return -1;
    }
  }

  if((wr + SIZE_FRAME_HEADER) < gs->s_rx_len){
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "incomplete packet transmission to %s: %d + %d < %u", gs->s_tap_name, SIZE_FRAME_HEADER, wr, gs->s_rx_len);
    /* WARNING: also ditches packet, otherwise we might have an unending stream of fragments (for some errors) */
    forget_receive(gs);
    return -1;
  }

  forget_receive(gs);

  return 1;
}

/* callback/scheduling parts ********************************************/

int run_timer_tap(struct katcp_dispatch *d, void *data)
{
  struct getap_state *gs;
  struct katcp_arb *a;
  int result, run;
  unsigned int burst;
  struct tbs_raw *tr;

  gs = data;
  sane_gs(gs);

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return -1;
  }

  if(tr->r_fpga != TBS_FPGA_READY){
    log_message_katcp(d, KATCP_LEVEL_FATAL, NULL, "major problem, attempted to run %s despite fpga being down", gs->s_tap_name);
    return -1;
  }

  if (gs->s_dhcp_sm_enable == 1){
    dhcp_statemachine(gs);
  }

  a = gs->s_tap_io;

  /* attempt to flush out stuff still stuck in buffers */

  if(gs->s_arp_len > 0){
    result = write_frame_fpga(gs, gs->s_arp_buffer, gs->s_arp_len);
    if(result != 0){
      gs->s_arp_len = 0;
      if(result > 0){
        gs->s_tx_arp++;
      } else {
        gs->s_tx_error++;
      }
    }
  }

  if(gs->s_tx_len > 0){
    result = write_frame_fpga(gs, gs->s_txb, gs->s_tx_len);
    if(result != 0){
      gs->s_tx_len = 0;
      if(result > 0){
        gs->s_tx_user++;
      } else {
        gs->s_tx_error++;
      }
    }
  }

  burst = 0;
  run = 1;

  /* TODO: might want to handle burst of traffic better, instead of waiting poll interval for next frame */
  do{

    if(receive_frame_fpga(gs) > 0){

      if(gs->s_rx_len > gs->s_rx_big){
        gs->s_rx_big = gs->s_rx_len;
      }
      if(gs->s_rx_len < gs->s_rx_small){
        gs->s_rx_small = gs->s_rx_len;
      }

      if(gs->s_rxb[FRAME_TYPE1] == 0x08){
        switch(gs->s_rxb[FRAME_TYPE2]){
          case 0x00 : /* IP packet */

            if (validate_dhcp_reply(gs) == 1){
                if (gs->s_dhcp_valid_dhcp == 0){
                    gs->s_dhcp_valid_dhcp = 1;
                    memcpy(gs->s_dhcp_rx_buffer, gs->s_rxb, gs->s_rx_len);
                }
                forget_receive(gs);
            } else {
                if(transmit_ip_kernel(gs) == 0){
                printf("******************\n");
                    /* attempt another transmit when tfd becomes writable */
                    mode_arb_katcp(d, a, KATCP_ARB_READ | KATCP_ARB_WRITE);
                    run = 0; /* don't bother getting more if we can't send it on */
                }
            }
            gs->s_rx_user++;
            break;

          case 0x06 : /* arp packet */
            
            if(gs->s_address_binary != 0){
              result = process_arp(gs);
              if(result == 0){
                gs->s_rx_arp++;
                run = 0; /* arp reply stalled, wait ... */
              } else {
                if(result < 0){
                  gs->s_rx_error++;
                } else {
                  gs->s_rx_arp++;
                }
              }
            }
            forget_receive(gs);
            break;

          default :

            log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "discarding frame of unknown type 0x%02x%02x and length %d", gs->s_rxb[FRAME_TYPE1], gs->s_rxb[FRAME_TYPE2], gs->s_rx_len);
            gs->s_rx_error++;
            forget_receive(gs);

            break;
        }
      } else {
        gs->s_rx_error++;
        forget_receive(gs);
      }

      burst++;

      if(burst > gs->s_burst){
        run = 0;
      }

    } else { /* nothing more to receive */
      run = 0;
    }
  } while(run);

#if DEBUG > 1
  fprintf(stderr, "run timer loop: burst now %d\n", burst);
#endif

  if((gs->s_address_binary != 0) && (gs->s_arp_mode != ARP_MODE_OFF)){
    if(burst < (gs->s_deferrals + 1)){ /* try to spam the network if it is reasonably quiet, but adjust our definition of quiet */
      spam_arp(gs);
      gs->s_deferrals = 0;
    } else {
      gs->s_deferrals++;
    }
  }

  return 0;
}

int run_io_tap(struct katcp_dispatch *d, struct katcp_arb *a, unsigned int mode)
{
  struct getap_state *gs;
  int result;
  struct tbs_raw *tr;

  gs = data_arb_katcp(d, a);
  sane_gs(gs);

  tr = get_current_mode_katcp(d);

  if(tr && (tr->r_fpga == TBS_FPGA_READY)){ /* WARNING: actually we should never run if fpga not mapped */

    if(mode & KATCP_ARB_READ){
      result = receive_ip_kernel(d, gs);
      if(result > 0){
        transmit_ip_fpga(gs); /* if it doesn't work out, hope that next schedule will clear it */
      }
    }

    if(mode & KATCP_ARB_WRITE){
      if(transmit_ip_kernel(gs) != 0){ /* unless we have to defer again disable write select */
        mode_arb_katcp(d, a, KATCP_ARB_READ);
      }
    }
  }

  return 0;
}

/* configure fpga *******************************************************/

int configure_ip_fpga(struct getap_state *gs)
{
  struct in_addr in;
  uint32_t value;
  void *base;
  struct katcp_dispatch *d;
  char *ptr;

  sane_gs(gs);

  d = gs->s_dispatch;
  base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base;

  /* TODO: make this atomic/transactional - only write values when happy with all of them */

  ptr = strchr(gs->s_address_name, '/');
  if(ptr != NULL){
    ptr[0] = '\0';
    ptr++;
    gs->s_subnet = atoi(ptr);
    if((gs->s_subnet < MAX_SUBNET) || (gs->s_subnet > 30)){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "size problem of subnet /%u in %s", gs->s_subnet, gs->s_address_name);
      return -1;
    }
  }

  if(inet_aton(gs->s_address_name, &in) == 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to parse %s to ip address", gs->s_address_name);
    return -1;
  }
  if(sizeof(in.s_addr) != 4){
    log_message_katcp(d, KATCP_LEVEL_FATAL, NULL, "major logic problem: ip address not 4 bytes");
    return -1;
  }

  value = in.s_addr;
  *((uint32_t *)(base + GO_ADDRESS)) = value;
  gs->s_address_binary = value; /* in network byte order */

  gs->s_mask_binary = htonl((0xffffffff << (32 - gs->s_subnet))); 
  gs->s_network_binary = gs->s_mask_binary & gs->s_address_binary;
  gs->s_self = ntohl(~(gs->s_mask_binary) & gs->s_address_binary);

  if(gs->s_gateway_name[0] != '\0'){
    if(inet_aton(gs->s_gateway_name, &in) == 0){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to parse gateway %s to ip address", gs->s_gateway_name);
      return -1;
    }
    value = (in.s_addr) & 0xff; /* WARNING: unclear why this has to be masked */
    *((uint32_t *)(base + GO_GATEWAY)) = value;
    gs->s_gateway_binary = value;
  } else {
    gs->s_gateway_binary = 0;
  }

  return 0;
}

int configure_fpga(struct getap_state *gs)
{
  uint32_t value;
  unsigned int i;
  void *base;
  struct katcp_dispatch *d;

  sane_gs(gs);

  d = gs->s_dispatch;
  base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base;

  if(text_to_mac(gs->s_mac_binary, gs->s_mac_name) < 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to parse %s to a mac address", gs->s_mac_name);
    return -1;
  }
  if(write_mac_fpga(gs, GO_MAC, gs->s_mac_binary) < 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to tell gateware about our own mac %s", gs->s_mac_name);
    return -1;
  }

  memcpy(gs->s_txb + 6, gs->s_mac_binary, 6);
  gs->s_txb[FRAME_TYPE1] = 0x08;
  gs->s_txb[FRAME_TYPE2] = 0x00;

  /* remove later with configure ip */
  if(configure_ip_fpga(gs) < 0){
    return -1;
  }

  /* assumes plain big endian value */
  /* Bitmask: 24   : Reset core */
  /*          16   : Enable fabric interface */
  /*          00-15: Port */

  if(gs->s_port == 0){
    value = *((uint32_t *)(base + GO_EN_RST_PORT));
    gs->s_port = 0xffff & value;
  }

#if 1
  /* First, reset the core */
  value = (0xff << 16) + (0xff << 16) + (gs->s_port);
  *((uint32_t *)(base + GO_EN_RST_PORT)) = value;

  /* Next, remove core from reset state: */
  value = (0x00 << 16) + (0xff << 16) + (gs->s_port);
  *((uint32_t *)(base + GO_EN_RST_PORT)) = value;
#else
  value = 0x01010000 | (0xffff & (gs->s_port));
  *((uint32_t *)(base + GO_EN_RST_PORT)) = value;
#endif

  for(i = 0; i < GETAP_ARP_CACHE; i++){
    /* heuristic to make things less bursty ... unclear if it is worth anything in large networks */
    set_entry_arp(gs, i, broadcast_const, 2 + ((gs->s_self + (i * COPRIME_C)) % (GETAP_ARP_CACHE / CACHE_DIVISOR)));
  }

  if(gs->s_self > 0){
    set_entry_arp(gs, gs->s_self, gs->s_mac_binary, 1);
  }

  return 0;
}

/* configure tap device *************************************************/

static int configure_tap(struct getap_state *gs)
{
  char cmd_buffer[CMD_BUFFER];
  int len;

  if(gs->s_address_binary != 0){
    len = snprintf(cmd_buffer, CMD_BUFFER, "ifconfig %s %s netmask 255.255.255.0 up\n", gs->s_tap_name, gs->s_address_name);
  } else {
    len = snprintf(cmd_buffer, CMD_BUFFER, "ifconfig %s %s up\n", gs->s_tap_name, gs->s_address_name);
  }

  if((len < 0) || (len >= CMD_BUFFER)){
    return -1;
  }
  cmd_buffer[CMD_BUFFER - 1] = '\0';

  /* WARNING: stalls the system, could possibly handle it via a job command */
  if(system(cmd_buffer)){
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_WARN, NULL, "unable to configure ip address using %s", gs->s_address_name);
    return -1;
  }

  return 0;
}

/* state allocations ****************************************************/

void destroy_getap(struct katcp_dispatch *d, struct getap_state *gs)
{
  /* WARNING: destroy_getap, does not remove itself from the global structure */

  sane_gs(gs);

  /* make all the callbacks go away */

  if(gs->s_tap_io){
    unlink_arb_katcp(d, gs->s_tap_io);
    gs->s_tap_io = NULL;
  }

  if(gs->s_timer){
    discharge_timer_katcp(d, gs);
    gs->s_timer = 0;
  }

  /* empty out the rest of the data structure */

  if(gs->s_tap_fd >= 0){
#if 0
    /* unlink arb does this for us */
    tap_close(gs->s_tap_fd);
#endif
    gs->s_tap_fd = (-1);
  }

  if(gs->s_tap_name){
    free(gs->s_tap_name);
    gs->s_tap_name = NULL;
  }

  if (gs->s_mcast_fd > 0){
    close(gs->s_mcast_fd);
    gs->s_mcast_fd = (-1);
  }

  gs->s_mcast_count = 0;

  /* now ensure that things are invalidated */

  gs->s_raw_mode = NULL;
  gs->s_register = NULL;
  gs->s_dispatch = NULL;

  gs->s_port = 0;
  gs->s_self = 0;
  gs->s_index = 0;
#if 0
  gs->s_period = 0;
#endif
  gs->s_iteration = 0;

  gs->s_rx_len = 0;
  gs->s_tx_len = 0;
  gs->s_arp_len = 0;

  gs->s_magic = 0;

  gs->s_x_glean = (-1);
  gs->s_arp_mode = ARP_MODE_OFF;

  gs->s_rx_error = (-1);
  gs->s_tx_error = (-1);

  free(gs);
}

void unlink_getap(struct katcp_dispatch *d, struct getap_state *gs)
{
  unsigned int i;
  struct tbs_raw *tr;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return;
  }

  i = 0; 
  while(i < tr->r_instances){
    if(tr->r_taps[i] == gs){
      tr->r_instances--;
      if(i < tr->r_instances){
        tr->r_taps[i] = tr->r_taps[tr->r_instances];
      }
    } else {
      i++;
    }
  }

  destroy_getap(d, gs);
}

void stop_all_getap(struct katcp_dispatch *d, int final)
{
  unsigned int i;
  struct tbs_raw *tr;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return;
  }

  if(tr->r_taps == NULL){
    return;
  }

  for(i = 0; i < tr->r_instances; i++){
    if(!final){
      log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "obliged to stop running tap instance %s before resetting fpga", tr->r_taps[i]->s_tap_name);
    }
    destroy_getap(d, tr->r_taps[i]);
    tr->r_taps[i] = NULL;
  }

  tr->r_instances = 0;

  if(final){
    free(tr->r_taps);
    tr->r_taps = NULL;
  }

}

/*************************************************************************************/

struct getap_state *create_getap(struct katcp_dispatch *d, unsigned int instance, char *name, char *tap, char *ip, unsigned int port, char *mac, char *gateway, unsigned int period)
{
  struct getap_state *gs; 
  unsigned int i;
  struct tbs_raw *tr;

  gs = NULL;

#ifdef DEBUG
  fprintf(stderr, "attempting to set up tap device %s from register %s (ip=%s, mac=%s)\n", tap, name, ip, mac);
#endif

  log_message_katcp(d, KATCP_LEVEL_DEBUG, NULL, "attempting to set up tap device %s", tap);

  tr = get_mode_katcp(d, TBS_MODE_RAW);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "need raw mode for tap operation");
    return NULL;
  }

  if(tr->r_fpga != TBS_FPGA_READY){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "fpga not mapped, unable to run tap logic");
    return NULL;
  }

  gs = malloc(sizeof(struct getap_state));
  if(gs == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to allocate state for %s", name);
    return NULL;
  }

  gs->s_magic = GS_MAGIC;

  gs->s_dispatch = d;
  gs->s_raw_mode = NULL;

  gs->s_tap_name = NULL;

  gs->s_address_name[0] = '\0';
  gs->s_gateway_name[0] = '\0';
  gs->s_mac_name[0] = '\0';
  gs->s_port = GO_DEFAULT_PORT;
  gs->s_subnet = 24;

  gs->s_self = 0;
  gs->s_index = 1;
#if 0
  gs->s_period = FRESH_ANNOUNCE_INITIAL;
#endif

  /* mac, address, mask, network binary */

  gs->s_instance = instance;
  gs->s_iteration = 0;
  gs->s_burst = RECEIVE_BURST;
  gs->s_deferrals = 0;

  gs->s_announce_period[GETAP_PERIOD_START    ] = ANNOUNCE_INITIAL;
  gs->s_announce_period[GETAP_PERIOD_STOP     ] = ANNOUNCE_FINAL;
  gs->s_announce_period[GETAP_PERIOD_INCREMENT] = ANNOUNCE_STEP;
  gs->s_announce_period[GETAP_PERIOD_CURRENT  ] = gs->s_announce_period[GETAP_PERIOD_START];

  gs->s_spam_period[GETAP_PERIOD_START    ] = SPAM_INITIAL;
  gs->s_spam_period[GETAP_PERIOD_STOP     ] = SPAM_FINAL;
  gs->s_spam_period[GETAP_PERIOD_INCREMENT] = SPAM_STEP;
  gs->s_spam_period[GETAP_PERIOD_CURRENT  ] = gs->s_spam_period[GETAP_PERIOD_START];

  gs->s_valid_period = FRESH_VALID;

  gs->s_register = NULL;

  gs->s_tap_io = NULL;
  gs->s_tap_fd = (-1);
  gs->s_mcast_fd = (-1);
  gs->s_mcast_count = 0;

  gs->s_timer = 0;

  gs->s_rx_len = 0;
  gs->s_tx_len = 0;
  gs->s_arp_len = 0;

  gs->s_tx_arp = 0;
  gs->s_tx_user = 0;
  gs->s_tx_error = 0;

  gs->s_rx_arp = 0;
  gs->s_rx_user = 0;
  gs->s_rx_error = 0;

  gs->s_rx_big = 0;
  gs->s_rx_small = GETAP_MAX_FRAME + 1;

  gs->s_tx_big = 0;
  gs->s_tx_small = GETAP_MAX_FRAME + 1;

  gs->s_x_glean = 0;
  gs->s_arp_mode = ARP_MODE_DEFAULT;

  gs->s_table_size = 1;
  for(i = gs->s_subnet; i < 32; i++){
    gs->s_table_size = gs->s_table_size * 2;
  }

  if((gs->s_table_size > GETAP_ARP_CACHE) || (gs->s_table_size < 4)){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "%u-2 stations in /%u subnet is unreasonable", gs->s_table_size, gs->s_subnet);
    destroy_getap(d, gs);
    return NULL;
  }

  /* buffers, table */

  for(i = 0; i < GETAP_ARP_CACHE; i++){
    gs->s_arp_fresh[i] = i;
  }

  /* initialise the rest of the structure here */
  gs->s_raw_mode = tr;

  gs->s_register = find_data_avltree(gs->s_raw_mode->r_registers, name);
  if(gs->s_register == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "no register of name %s available", name);
    destroy_getap(d, gs);
    return NULL;
  }

  gs->s_tap_name = strdup(tap);
  if(gs->s_tap_name == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to duplicate tap device name %s", tap);
    destroy_getap(d, gs);
    return NULL;
  }

  strncpy(gs->s_address_name, ip, GETAP_IP_BUFFER);
  gs->s_address_name[GETAP_IP_BUFFER - 1] = '\0';

  if(gateway){
    strncpy(gs->s_gateway_name, gateway, GETAP_IP_BUFFER);
    gs->s_gateway_name[GETAP_IP_BUFFER - 1] = '\0';
  }

  if(mac){
    strncpy(gs->s_mac_name, mac, GETAP_MAC_BUFFER);
  } else {
    generate_text_mac(gs->s_mac_name, gs->s_instance); /* TODO: increment index somehow */
    log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "generated mac %s", gs->s_mac_name);
  }

  if(port > 0){
    gs->s_port = port;
  }

  if(configure_fpga(gs) < 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to initialise gateware on %s", name);
    destroy_getap(d, gs);
    return NULL;
  }

  gs->s_tap_fd = tap_open(gs->s_tap_name);
  if(gs->s_tap_fd < 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to create tap device %s", gs->s_tap_name);
    destroy_getap(d, gs);
    return NULL;
  }

  gs->s_tap_io = create_arb_katcp(d, gs->s_tap_name, gs->s_tap_fd, KATCP_ARB_READ, &run_io_tap, gs);
  if(gs->s_tap_io == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to create io handler for tap device %s", gs->s_tap_name);
    tap_close(gs->s_tap_fd);
    destroy_getap(d, gs);
    return NULL;
  }

  if(configure_tap(gs)){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to configure tap device");
    destroy_getap(d, gs);
    return NULL;
  }

  if(register_every_ms_katcp(d, period, &run_timer_tap, gs) < 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to register timer for interval of %dms", gs->s_timer);
    destroy_getap(d, gs);
    return NULL;
  }

  gs->s_timer = period; /* a nonzero value here means the timer is running ... */

  return gs;
}

int insert_getap(struct katcp_dispatch *d, char *name, char *tap, char *ip, unsigned int port, char *mac, char *gateway, unsigned int period)
{
  struct getap_state *gs, **tmp; 
  unsigned int i;
  struct tbs_raw *tr;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return -1;
  }

  i = 0; 
  while(i < tr->r_instances){
    if(!strcmp(tap, tr->r_taps[i]->s_tap_name)){
      log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "tap device %s already running, restarting it", tap);
      destroy_getap(d, tr->r_taps[i]);
      tr->r_instances--;
      if(i < tr->r_instances){
        tr->r_taps[i] = tr->r_taps[tr->r_instances];
      }
    } else {
      i++;
    }
  }

  gs = create_getap(d, tr->r_instances, name, tap, ip, port, mac, gateway, period);
  if(gs == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "failed to set up tap devices %s on register %s", tap, name);
    return -1;
  }

  tmp = realloc(tr->r_taps, sizeof(struct getap_state *) * (tr->r_instances + 1));
  if(tmp == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to allocate memory for list of tap devices");
    return -1;
  }

  tr->r_taps = tmp;
  tr->r_taps[tr->r_instances] = gs;

  tr->r_instances++;

  return 0;
}

/* commands registered **************************************************/

int tap_start_cmd(struct katcp_dispatch *d, int argc)
{
  char *name, *tap, *ip, *mac, *gateway;
  unsigned int port;

  gateway = NULL;
  mac = NULL;
  port = 0;

  if(argc < 4){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "need at least a tap device name, register name and an ip address");
    return KATCP_RESULT_INVALID;
  }

  tap = arg_string_katcp(d,1);
  name = arg_string_katcp(d, 2);
  ip = arg_string_katcp(d, 3);

  if((tap == NULL) || (ip == NULL) || (name == NULL)){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to acquire essential parameters");
    return KATCP_RESULT_INVALID;
  }

  if(argc > 4){
    port = arg_unsigned_long_katcp(d, 4);
    if(port == 0){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to acquire optional port");
      return KATCP_RESULT_INVALID;
    }

    if(argc > 5){
      mac = arg_string_katcp(d, 5);
#if 0
      if(mac == NULL){
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to acquire optional mac");
        return KATCP_RESULT_INVALID;
      }
#endif

      if(argc > 6){
        gateway = arg_string_katcp(d, 6);
        if(gateway == NULL){
          log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to acquire optional gateway");
          return KATCP_RESULT_INVALID;
        }
      }
    }
  }

  if(insert_getap(d, name, tap, ip, port, mac, gateway, POLL_INTERVAL) < 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to initialise tap component");
    return KATCP_RESULT_INVALID;
  }

  return KATCP_RESULT_OK;
}

int tap_stop_cmd(struct katcp_dispatch *d, int argc)
{
  char *name;
  struct katcp_arb *a;
  struct getap_state *gs;

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

  unlink_getap(d, gs);

  return KATCP_RESULT_OK;
}

void tap_reload_arp(struct katcp_dispatch *d, struct getap_state *gs)
{
  unsigned int i;

  log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "forcing re-acquire of network peers for %s", gs->s_tap_name);

  for(i = 1; i < (GETAP_ARP_CACHE - 1); i++){
#if 0
    gs->s_arp_fresh[i] = gs->s_iteration + (i * COPRIME_A) + 1;
#endif
    gs->s_arp_fresh[i] = gs->s_iteration + (2 + ((gs->s_self + (i * COPRIME_C)) % (GETAP_ARP_CACHE / CACHE_DIVISOR)));
  }

  if(gs->s_self > 0){
    set_entry_arp(gs, gs->s_self, gs->s_mac_binary, 1);
  }

  /* WARNING: probably bad form - should clear everything or nothing */
  gs->s_rx_arp = 0;
  gs->s_tx_arp = 0;
}

int tap_reload_cmd(struct katcp_dispatch *d, int argc)
{
  char *name;
  unsigned int i;
  struct tbs_raw *tr;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return KATCP_RESULT_FAIL;
  }

  if(argc <= 1){
    for(i = 0; i < tr->r_instances; i++){
      tap_reload_arp(d, tr->r_taps[i]);
    }

    return KATCP_RESULT_OK;
  }
  
  name = arg_string_katcp(d, 1);
  if(name == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "internal failure while acquiring parameters");
    return KATCP_RESULT_FAIL;
  }

  for(i = 0; i < tr->r_instances; i++){
    if(!strcmp(tr->r_taps[i]->s_tap_name, name)){
      tap_reload_arp(d, tr->r_taps[i]);
      return KATCP_RESULT_OK;
    }
  }

  log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "no active tap instance %s found", name);

  return KATCP_RESULT_FAIL;
}

int tap_runtime_configure(struct katcp_dispatch *d, struct getap_state *gs, char *key, char *value)
{
  unsigned long v;
  char *ptr;
  int valid, len;
  unsigned int *array, index;

  if(key == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "no key given");
    return -1;
  }

  if(value == NULL){
    valid = 0;
  } else {
    v = strtoul(value, &ptr, 0);
    if(ptr[0] == '\0'){
      valid = 1;
    } else {
      valid = (-1);
    }
  }

  ptr = strchr(key, '-');
  if(ptr == NULL){
    len = strlen(key);
  } else {
    len = ptr - key;
  }

  if(!strcmp(key, "mode")){
    if(value){
      if(!strcmp(value, "off")){
        gs->s_arp_mode = 0;
      } else if(!strcmp(value, "loop")){
        gs->s_arp_mode = (-1);
      } else if(!strcmp(value, "once")){
        gs->s_arp_mode = 1;
      } else {
        gs->s_arp_mode = v;
      }
    } else {
      gs->s_arp_mode = 0;
    }

    if(gs->s_arp_mode <= 0){
      log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "will %s run arp queries", (gs->s_arp_mode < 0) ? "continously" : "not");
    } else {
      log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "will run arp queries for %d cycles", gs->s_arp_mode);
      gs->s_index = 1;
    }

  } else if(!strncmp(key, "valid-", len)){
    if(valid >= 0){
      if(valid > 0){
        gs->s_valid_period = v;
      }
      log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "live stations valid for %ums", gs->s_valid_period * POLL_INTERVAL);
    } else {
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "invalid configuration value %s", value);
    }
  } else if(!(strncmp(key, "query-", len) && strncmp(key, "announce-", len))){
    if(!strncmp(key, "query-", len)){
      array = gs->s_spam_period;
    } else {
      array = gs->s_announce_period;
    }

    ptr = key + len;
    if(ptr[0] == '-'){
      if(!strcmp(ptr, "-start")){
        index = GETAP_PERIOD_START;
      } else if(!strcmp(ptr, "-stop")){
        index = GETAP_PERIOD_STOP;
      } else if(!strcmp(ptr, "-step")){
        index = GETAP_PERIOD_INCREMENT;
      } else {
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "invalid configuration setting %s", key);
        index = (-1);
        return -1;
      }
    }
    if(valid >= 0){
      if(valid > 0){
        array[index] = v;
      }
      if(array[GETAP_PERIOD_START] > array[GETAP_PERIOD_STOP]){
        v = array[GETAP_PERIOD_START];
        array[GETAP_PERIOD_START] = array[GETAP_PERIOD_STOP];
        array[GETAP_PERIOD_STOP] = v;
      }
      if(array[GETAP_PERIOD_CURRENT] > array[GETAP_PERIOD_START]){
        array[GETAP_PERIOD_CURRENT] = array[GETAP_PERIOD_START];
      }
      log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "%s set to %ums", key, array[index] * POLL_INTERVAL);
    } else {
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "invalid configuration value %s", value);
    }
  } else {
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unknown configuration setting %s", key);
    return -1;
  }

  return 0;
}

int tap_config_cmd(struct katcp_dispatch *d, int argc)
{
  char *name, *key, *value;
  unsigned int i;
  struct tbs_raw *tr;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return KATCP_RESULT_FAIL;
  }

  if(argc <= 2){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "need a device and setting");
    return KATCP_RESULT_FAIL;
  }
  
  name = arg_string_katcp(d, 1);
  if(name == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "internal failure while acquiring device name");
    return KATCP_RESULT_FAIL;
  }

  key = arg_string_katcp(d, 2);
  if(key == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "internal failure while acquiring configuration setting for %s", name);
    return KATCP_RESULT_FAIL;
  }

  if(argc > 2){
    value = arg_string_katcp(d, 3);
  } else {
    value = NULL;
  }

  for(i = 0; i < tr->r_instances; i++){
    if(!strcmp(tr->r_taps[i]->s_tap_name, name)){
      return (tap_runtime_configure(d, tr->r_taps[i], key, value) < 0) ? KATCP_RESULT_FAIL : KATCP_RESULT_OK;
    }
  }

  log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "no active tap instance %s found", name);

  return KATCP_RESULT_FAIL;
}

static void tap_print_period_info(struct katcp_dispatch *d, char *prefix, unsigned int *array)
{
  log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "%s period initially every %ums currently %ums incrementing by %ums until %ums", prefix, array[GETAP_PERIOD_START] * POLL_INTERVAL, array[GETAP_PERIOD_CURRENT] * POLL_INTERVAL, array[GETAP_PERIOD_INCREMENT] * POLL_INTERVAL, array[GETAP_PERIOD_STOP] * POLL_INTERVAL);
}

void tap_print_info(struct katcp_dispatch *d, struct getap_state *gs)
{
  unsigned int i;
  uint32_t link;

  link = link_status_fpga(gs);

  /* WARNING: probably abusing the subnet table entry (0) horribly to display a mac address for 0.0.0.0, normally we should always start at 1 */
  for(i = 1; i < (GETAP_ARP_CACHE - 1); i++){
    log_message_katcp(gs->s_dispatch, memcmp(gs->s_arp_table[i], broadcast_const, 6) ? KATCP_LEVEL_INFO : KATCP_LEVEL_TRACE, NULL, "%s %02x:%02x:%02x:%02x:%02x:%02x at index %u valid for %ums", (gs->s_self == i) ? "self" : "peer", gs->s_arp_table[i][0], gs->s_arp_table[i][1], gs->s_arp_table[i][2], gs->s_arp_table[i][3], gs->s_arp_table[i][4], gs->s_arp_table[i][5], i, (gs->s_arp_fresh[i] - gs->s_iteration) * POLL_INTERVAL);
  }

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "mac %02x:%02x:%02x:%02x:%02x:%02x", gs->s_mac_binary[0], gs->s_mac_binary[1], gs->s_mac_binary[2], gs->s_mac_binary[3], gs->s_mac_binary[4], gs->s_mac_binary[5]);

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_DEBUG, NULL, "own index %u", gs->s_self);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "current iteration %u", gs->s_iteration);

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "polling interval %ums", gs->s_timer);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "max reads per interval %u", gs->s_burst);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "address %s", gs->s_address_name);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "subnet is /%u with %u-2 stations", gs->s_subnet, gs->s_table_size);
  if(gs->s_gateway_name[0] != '\0'){
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "fabric gateway %s", gs->s_gateway_name);
  }
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "gateware port is %u", gs->s_port);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "tap device name %s on fd %d", gs->s_tap_name, gs->s_tap_fd);

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "valid entries cached for %ums", gs->s_valid_period * POLL_INTERVAL);

  if((gs->s_arp_mode != ARP_MODE_OFF) && (gs->s_address_binary != 0)){
    if(gs->s_arp_mode > 0){
      log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "arp will loop another %d times", gs->s_arp_mode);
    } else {
      log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "arp will query indefinitely");
    }
    tap_print_period_info(d, "announce", gs->s_announce_period);
    tap_print_period_info(d, "query",    gs->s_spam_period);
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "current arp spam deferrals %u", gs->s_deferrals);
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "current index %u", gs->s_index);
  } else {
    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "arp request loop is not active");
  }

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "current buffers arp=%u/rx=%u/tx=%u", gs->s_arp_len, gs->s_rx_len, gs->s_tx_len);

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "subscribed to %d groups via fd=%d", gs->s_mcast_count, gs->s_mcast_fd);

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "TX arp=%lu user=%lu error=%lu total=%lu", gs->s_tx_arp, gs->s_tx_user, gs->s_tx_error, gs->s_tx_arp + gs->s_tx_user);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "TX sizes smallest=%u biggest=%u", gs->s_tx_small, gs->s_tx_big);

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "RX arp=%lu user=%lu error=%lu total=%lu", gs->s_rx_arp, gs->s_rx_user, gs->s_rx_error, gs->s_rx_arp + gs->s_rx_user);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "RX sizes smallest=%u biggest=%u", gs->s_rx_small, gs->s_rx_big);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "arp requests used to glean stations %u", gs->s_x_glean);
  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "link status word is 0x%08x", link);

  log_message_katcp(gs->s_dispatch, KATCP_LEVEL_DEBUG, NULL, "binary: ip=%08x, netmask=%08x, subnet=%08x", gs->s_address_binary, gs->s_mask_binary, gs->s_network_binary);

  prepend_inform_katcp(d);
  append_string_katcp(d, KATCP_FLAG_STRING, gs->s_tap_name);
  append_string_katcp(d, KATCP_FLAG_STRING | KATCP_FLAG_LAST, gs->s_address_name);
}

int tap_info_cmd(struct katcp_dispatch *d, int argc)
{
  char *name;
  unsigned int i;
  struct tbs_raw *tr;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return KATCP_RESULT_FAIL;
  }

  if(argc <= 1){
    for(i = 0; i < tr->r_instances; i++){
      tap_print_info(d, tr->r_taps[i]);
    }

    return KATCP_RESULT_OK;
  }
  
  name = arg_string_katcp(d, 1);
  if(name == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "internal failure while acquiring parameters");
    return KATCP_RESULT_FAIL;
  }

  for(i = 0; i < tr->r_instances; i++){
    if(!strcmp(tr->r_taps[i]->s_tap_name, name)){
      tap_print_info(d, tr->r_taps[i]);
      return KATCP_RESULT_OK;
    }
  }

  log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "no active tap instance %s found", name);

  return KATCP_RESULT_FAIL;
}

int tap_ip_config_cmd(struct katcp_dispatch *d, int argc)
{
  struct katcp_arb *a;
  char *name, *ip, *gateway;
  struct getap_state *gs;

  gateway = NULL;
  ip = NULL;
  name = NULL;

  if(argc < 2){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "need at least a device name and ip address");
    return KATCP_RESULT_INVALID;
  }

  name = arg_string_katcp(d, 1);
  ip = arg_string_katcp(d, 2);
  gateway = arg_string_katcp(d, 3);

  if((name == NULL) || (ip == NULL)){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to acquire essential parameters");
    return KATCP_RESULT_INVALID;
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

  strncpy(gs->s_address_name, ip, GETAP_IP_BUFFER);
  gs->s_address_name[GETAP_IP_BUFFER - 1] = '\0';

  if(gateway){
    strncpy(gs->s_gateway_name, gateway, GETAP_IP_BUFFER);
    gs->s_gateway_name[GETAP_IP_BUFFER - 1] = '\0';
  }

  if(configure_ip_fpga(gs) < 0){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to make requested changes for %s", name);
    return KATCP_RESULT_FAIL;
  }

  tap_reload_arp(d, gs);

  return KATCP_RESULT_OK;
}

int is_power_of_two(unsigned int value)
{
  unsigned int t;

  t = value;

  if(t == 0){
    return 0;
  }

  while(t > 1){
    if(t & 1){
      return 0;
    } else {
      t = t >> 1;
    }
  }

  return 1;
}

int tap_multicast_add_group_cmd(struct katcp_dispatch *d, int argc)
{
  struct tbs_raw *tr;
  struct katcp_arb *a;
  struct getap_state *gs;
  char *name, *mode, *addresses, *ptr;
  unsigned int count;
  
  uint32_t start;

  void *base    = NULL;
  uint32_t mask = 0xFFFFFFFF;
  int i;

  /*recv*/
  int reuse = 1, loopch = 0;
  struct sockaddr_in  locosock;
  //struct ip_mreq        grp;
  
  /*send*/
  struct in_addr        locoif;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return KATCP_RESULT_FAIL;
  }

  if (argc < 4){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "usage tap-name [recv|send] multicast-address");
    return KATCP_RESULT_FAIL;
  }
  
  name = arg_string_katcp(d, 1);
  if(name == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to acquire a nonempty name");
    return KATCP_RESULT_FAIL;
  }

  mode = arg_string_katcp(d, 2);
  if(mode == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "need a valid mode");
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

  if(gs->s_mcast_fd < 0){
    gs->s_mcast_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (gs->s_mcast_fd < 0){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to open multicast %s socket on %s", mode, name);
      return KATCP_RESULT_FAIL;
    }

    memset((char*) &locosock, 0, sizeof(locosock));
    locosock.sin_family       = AF_INET;
    locosock.sin_port         = htons(gs->s_port);

    if(inet_aton(gs->s_address_name, (struct in_addr *) &locosock.sin_addr.s_addr) == 0){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to parse %s to ip address", gs->s_address_name);
      return -1;
    }

    if (bind(gs->s_mcast_fd, (struct sockaddr *) &locosock, sizeof(locosock)) < 0){
      close(gs->s_mcast_fd);
      gs->s_mcast_fd = (-1);
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to bind multicast %s socket on %s (%s)", mode, name, strerror(errno));
      return KATCP_RESULT_FAIL;
    }

  } else {
    log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "note that gateware probably does not support multiple multicast ranges");
  }

  addresses = arg_copy_string_katcp(d, 3);
  if(addresses == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "allocation failure while aquiring paramter %u", 3);
    return KATCP_RESULT_FAIL;
  }

  ptr = strchr(addresses, '+');
  if(ptr){
    count = atoi(ptr + 1) + 1;
    ptr[0] = '\0';
  } else {
    count = 1;
  }

  start = ntohl(inet_addr(addresses));

  log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "request for %s maps to 0x%08x+%u", addresses, start, count - 1);

  free(addresses);

  if(!is_power_of_two(count)){
    /* Jason prefers us to error out, rather than warn, conversation from 2014-01-03 */
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "range %u does not appear to be a power of 2", count);
    return KATCP_RESULT_FAIL;
  }

  if((count - 1) & start){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "address 0x%08x does not start on a multiple of %u", start, count);
    return KATCP_RESULT_FAIL;
  }

  if (strncmp(mode,"recv", 4) == 0){

    if (setsockopt(gs->s_mcast_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0){
      log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "unable to set reuseaddr on mcast socket");
    }
    
    /*change to inet_aton*/
    //locosock.sin_addr.s_addr  = inet_addr(gs->s_address_name);
    
    base = gs->s_raw_mode->r_map + gs->s_register->e_pos_base;
    if (base){
      /*assign the multicast ip to the gateware*/
      *((uint32_t *)(base + GO_MCADDR)) = (uint32_t) htonl(start);
      /* Assign the multicast mast to the gateware, checked with Wes, Jason and Paul 2014-04-03 */
      *((uint32_t *)(base + GO_MCMASK)) = (uint32_t) mask - (uint32_t) (count - 1);
    }

    for(i = 0; i < count; i++){
      struct ip_mreq        grp;
      
      //log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "temp1: 0x%08X", temp1);

      grp.imr_interface.s_addr = inet_addr(gs->s_address_name);
      grp.imr_multiaddr.s_addr = htonl(start + i); 
      if (setsockopt(gs->s_mcast_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (struct ip_mreq *) &grp, sizeof(struct ip_mreq)) < 0){
        close(gs->s_mcast_fd);
        gs->s_mcast_fd = (-1);
        log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to add multicast membership to 0x%08x on %s (%s)", start + i, name, strerror(errno));
        return KATCP_RESULT_FAIL;
      }

      
      gs->s_mcast_count++;
      log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "assigned group %s (%d in total)", inet_ntoa(grp.imr_multiaddr), gs->s_mcast_count);
    }
    
  } else if (strncmp(mode, "send", 4) == 0){
    
    if (setsockopt(gs->s_mcast_fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *) &loopch, sizeof(loopch)) < 0){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to disable multicast loop back (%s)", strerror(errno));
      close(gs->s_mcast_fd);
      return KATCP_RESULT_FAIL;
    }

#if 0
    /*this may be unessesary*/
    locosock.sin_addr.s_addr = inet_addr(grpip);
#endif

    locoif.s_addr   = inet_addr(gs->s_address_name);
    if (setsockopt(gs->s_mcast_fd, IPPROTO_IP, IP_MULTICAST_IF, (char *) &locoif, sizeof(locoif)) < 0){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to set multicast back (%s)", strerror(errno));
      close(gs->s_mcast_fd);
      return KATCP_RESULT_FAIL;
    }

    gs->s_mcast_count++;
    
  } else {
    log_message_katcp(d, KATCP_LEVEL_ERROR , NULL, "invalid mode <%s> [send | recv]", mode);
    return KATCP_RESULT_FAIL;
  }
  
  return KATCP_RESULT_OK;
} 

int tap_multicast_remove_group_cmd(struct katcp_dispatch *d, int argc)
{
  struct tbs_raw *tr;
  struct katcp_arb *a;
  struct getap_state *gs;
  char *grpip, *name;
  
  struct ip_mreq grp;

  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return KATCP_RESULT_FAIL;
  }

  if (argc < 2){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "usage tap-name [multicast-address]");
    return KATCP_RESULT_FAIL;
  }

  name = arg_string_katcp(d, 1);

  log_message_katcp(d, KATCP_LEVEL_DEBUG, NULL, "attempting to remove multicast subscription from device %s", name);
  

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

  if(argc > 2){
    grpip = arg_string_katcp(d, 2);
    if(grpip){
      grp.imr_multiaddr.s_addr = inet_addr(grpip);
      grp.imr_interface.s_addr = inet_addr(gs->s_address_name);
      if (setsockopt(gs->s_mcast_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *) &grp, sizeof(grp)) < 0){
        log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "unable to drop multicast membership to %s on %s (%s)", grpip, name, strerror(errno));
        //close(gs->s_mcast_fd);
        //gs->s_mcast_fd = (-1);
        //return KATCP_RESULT_FAIL;
      } else {
        if(gs->s_mcast_count > 0){
          gs->s_mcast_count--;
        }
      }
    } else {
      log_message_katcp(d, KATCP_LEVEL_WARN, NULL, "unable to acquire multicast group for %s", name);
      return KATCP_RESULT_FAIL;
    }
  } else {
    log_message_katcp(d, KATCP_LEVEL_DEBUG, NULL, "releasing all multicast subscriptions for %s", name);
    gs->s_mcast_count = 0;
  }
  
  if(gs->s_mcast_count <= 0){
    close(gs->s_mcast_fd);
    gs->s_mcast_fd = (-1);
  }
  
  return KATCP_RESULT_OK;
} 

int tap_route_add_cmd(struct katcp_dispatch *d, int argc)
{
  struct tbs_raw *tr;
  struct katcp_arb *a;
  struct getap_state *gs;
  char *name, *gateway, *network, *mask;
  char cmd_buffer[CMD_BUFFER];
  int len;
  
  tr = get_current_mode_katcp(d);
  if(tr == NULL){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to get raw state");
    return KATCP_RESULT_FAIL;
  }

  if(argc < 3){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "usage tap-name address [network mask]");
    return KATCP_RESULT_FAIL;
  }
  
  name  = arg_string_katcp(d, 1);
  gateway = arg_string_katcp(d, 2);

  if((name == NULL) || (gateway == NULL)){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "unable to acquire needed parameters");
    return KATCP_RESULT_FAIL;
  }

  network = NULL;
  mask = NULL;

  if(argc > 3){
    network = arg_string_katcp(d, 3);
    if(argc > 4){
      mask = arg_string_katcp(d, 3);
    } else {
      mask = "255.255.255.0";
      log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "assuming a netmask of %s", mask);
    }
    if((network == NULL) || (mask == NULL)){
      log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "invalid subnet specification");
      return KATCP_RESULT_FAIL;
    }
  } else {
    log_message_katcp(d, KATCP_LEVEL_INFO, NULL, "setting default route to %s", gateway);
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

  if(network && mask){
    len = snprintf(cmd_buffer, CMD_BUFFER, "route add -net %s netmask %s gw %s dev %s\n", network, mask, gateway, name);
  } else {
    len = snprintf(cmd_buffer, CMD_BUFFER, "route add -net default gw %s\n", gateway);
  }

  if((len < 0) || (len >= CMD_BUFFER)){
    log_message_katcp(d, KATCP_LEVEL_ERROR, NULL, "command unreasonably long");
    return KATCP_RESULT_FAIL;
  }

  cmd_buffer[CMD_BUFFER - 1] = '\0';

  /* WARNING: stalls the system, could possibly handle it via a job command */
  if(system(cmd_buffer)){
    return KATCP_RESULT_FAIL;
  }

  return KATCP_RESULT_OK;
}

/**************************DHCP functions**************************/
#define DEBUG 2
static uint16_t dhcp_checksum(uint8_t *data, uint16_t index_start, uint16_t index_end){
    int i, len;
    uint16_t tmp=0;
    uint32_t chksm=0, carry=0;

    if (index_start > index_end){     //range indexing error
#ifdef DEBUG
        fprintf(stderr, "checksum calulation: buffer range error\n");
#endif
        return -1;
    }

    len = index_end - index_start + 1;

    for (i=index_start; i<(index_start+len); i+=2){
        tmp = (uint16_t) data[i];
        tmp = tmp << 8;
        if (i == (len-1)){     //last iteration - only valid for (len%2 == 1)
            tmp = tmp + 0;
        }
        else{
            tmp = tmp + (uint16_t) data[i+1];
        }

#if DEBUG > 1
        fprintf(stderr, "tmp=%5x\t",tmp);
#endif
        //get 1's complement of data
        tmp = ~tmp;
#if DEBUG > 1
        fprintf(stderr, "~tmp=%5x\t",tmp);
#endif
        //aggregate -> doing 16bit arithmetic within 32bit words to preserve overflow
        chksm = chksm + tmp;
#if DEBUG > 1
        fprintf(stderr, "chksm before carry=%5x\t",chksm);
#endif
        //get overflow
        carry = chksm >> 16;
#if DEBUG > 1
        fprintf(stderr, "carry=%5x\t",carry);
#endif
        //add to checksum
        chksm = (MASK16 & chksm) + carry;
#if DEBUG > 1
        fprintf(stderr, "chksm after carry=%5x\n",chksm);
#endif

    }
    return chksm;
}

static int dhcp_msg(struct getap_state *gs, DHCP_MSG_TYPE mt){
    uint16_t len=0, chksm=0, sec=0;
    uint8_t tmp_src_ip[4] = {0};
    uint8_t tmp_dst_ip[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t broadcast_const[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    int i=0;
    int ret=0;

    /*zero the buffer*/
    memset(gs->s_dhcp_tx_buffer, 0, GETAP_DHCP_BUFFER_SIZE);
    
    /*build up the dhcp packet*/

    /*ethernet frame stuff*/
    memcpy(gs->s_dhcp_tx_buffer + ETH_DST_OFFSET, broadcast_const, 6);
    memcpy(gs->s_dhcp_tx_buffer + ETH_SRC_OFFSET, gs->s_mac_binary, 6);

    /*frame type is IP*/
    gs->s_dhcp_tx_buffer[ETH_FRAME_TYPE_OFFSET] = 0x08;
    gs->s_dhcp_tx_buffer[ETH_FRAME_TYPE_OFFSET + 1] = 0x00;

    /*ip frame stuff*/
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_V_HIL_OFFSET] = 0x45;
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_TOS_OFFSET] = 0x00;
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_ID_OFFSET] = 0x00;
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_ID_OFFSET + 1] = 0x00;

    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_FLAG_FRAG_OFFSET] = 0x00;
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_FLAG_FRAG_OFFSET + 1] = 0x00;

    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_TTL_OFFSET] = 0x40;
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_PROT_OFFSET] = 0x11;

    //enter zeros for checksum calculation
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET] = 0x00;
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET + 1] = 0x00;

    memcpy(gs->s_dhcp_tx_buffer + IP_FRAME_START_INDEX + IP_DST_OFFSET, tmp_dst_ip, 4);
    memcpy(gs->s_dhcp_tx_buffer + IP_FRAME_START_INDEX + IP_SRC_OFFSET, tmp_src_ip, 4);

        /*TODO ip length and checksum to be calculated later*/

    /*udp frame stuff*/

    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_SRC_PORT_OFFSET] = 0x00;
    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_SRC_PORT_OFFSET + 1] = 0x44;
    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_DST_PORT_OFFSET] = 0x00;
    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_DST_PORT_OFFSET + 1] = 0x43;

    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_CHKSM_OFFSET] = 0x00;
    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_CHKSM_OFFSET + 1] = 0x00;

        /*TODO length to be calculated later, udp cahecksum not strictly required (make zero)*/


    /*bootp stuff*/
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_OPTYPE_OFFSET] = 0x01;
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_HWTYPE_OFFSET] = 0x01;
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_HWLEN_OFFSET] = 0x06;
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_HOPS_OFFSET] = 0x00;

    if (mt == DHCPDISCOVER){
        srand(time(NULL));
        gs->s_dhcp_xid = (uint32_t)rand();
        gs->s_dhcp_sec_start = time(NULL);
    }

    /*generally tried to work on byte level to avoid endianness issues*/
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET    ]= (uint8_t) ((gs->s_dhcp_xid >> 24) & 0xFF);
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET + 1]= (uint8_t) ((gs->s_dhcp_xid >> 16) & 0xFF);
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET + 2]= (uint8_t) ((gs->s_dhcp_xid >>  8) & 0xFF);
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET + 3]= (uint8_t) ((gs->s_dhcp_xid      ) & 0xFF);

    sec = time(NULL) - gs->s_dhcp_sec_start;
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_SEC_OFFSET] = (uint8_t) (sec >> 8);
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_SEC_OFFSET] = (uint8_t) (sec & 0xFF);

    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_FLAGS_OFFSET, 0x00, 2);

    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_CIPADDR_OFFSET, 0x00, 4);
    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_YIPADDR_OFFSET, 0x00, 4);
    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_SIPADDR_OFFSET, 0x00, 4);
    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_GIPADDR_OFFSET, 0x00, 4);

    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_CHWADDR_OFFSET, 0x00, 16);
    memcpy(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_CHWADDR_OFFSET, gs->s_mac_binary, 6);

    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_SNAME_OFFSET, '\0', 64);
    memset(gs->s_dhcp_tx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_FILE_OFFSET, '\0', 128);

    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET] = 0x63;
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET + 1] = 0x82;
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET + 2] = 0x53;
    gs->s_dhcp_tx_buffer[BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET + 3] = 0x63;

    /*dhcp stuff -> dhcp is implemeted as an extension to bootp through bootp options*/
    gs->s_dhcp_tx_buffer[DHCP_FRAME_START_INDEX + DHCP_MTYPE_OFFSET] = 53;
    gs->s_dhcp_tx_buffer[DHCP_FRAME_START_INDEX + DHCP_MTYPE_OFFSET + 1] = 1;
    gs->s_dhcp_tx_buffer[DHCP_FRAME_START_INDEX + DHCP_MTYPE_OFFSET + 2] = (uint8_t) mt;

    gs->s_dhcp_tx_buffer[DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET] = 61;
    gs->s_dhcp_tx_buffer[DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET + 1] = 7;
    gs->s_dhcp_tx_buffer[DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET + 2] = 1;
    memcpy(gs->s_dhcp_tx_buffer + DHCP_FRAME_START_INDEX + DHCP_CID_OFFSET + 3 , gs->s_mac_binary, 6);

    switch(mt){
        case DHCPDISCOVER:
#if 0
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET] = 55;
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 1] = 5;
            /*request the following parameters*/
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 2] = 1;  //subnet mask
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 3] = 3;  //router
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 4] = 6;  //dname svr
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 5] = 12; //host name
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 6] = 15; //domain name
#endif
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_END_DISC_OFFSET] = 0xFF;
            len = DHCP_DISC_VAR_TOTAL_LEN;
            break;

        case DHCPREQUEST:

            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_SVRID_OFFSET] = 54;
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_SVRID_OFFSET + 1] = 4;
            memcpy(gs->s_dhcp_tx_buffer + DHCP_VAR_START_INDEX + DHCP_SVRID_OFFSET + 2, gs->s_dhcp_sip_addr, 4);
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET] = 55;
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 1] = 5;
            /*request the following parameters*/
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 2] = 1;  //subnet mask
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 3] = 3;  //router
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 4] = 6;  //dname svr
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 5] = 12; //host name
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_PARAM_OFFSET + 6] = 15; //domain name

            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_REQIP_OFFSET] = 50;
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_REQIP_OFFSET + 1] = 4;
            memcpy(gs->s_dhcp_tx_buffer + DHCP_VAR_START_INDEX + DHCP_REQIP_OFFSET + 2, gs->s_dhcp_yip_addr, 4);
            gs->s_dhcp_tx_buffer[DHCP_VAR_START_INDEX + DHCP_END_REQ_OFFSET] = 0xFF;
            len = DHCP_REQ_VAR_TOTAL_LEN;
            break;

        default:
#ifdef DEBUG
            fprintf(stderr, "dhcp message type '%d' not implemented\n", mt);
#endif
            return -1;
    }

    /*calculate packet lengths*/
    //udp_frame_len 
    len =  len + UDP_FRAME_TOTAL_LEN + BOOTP_FRAME_TOTAL_LEN + DHCP_FIXED_TOTAL_LEN;
    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_ULEN_OFFSET] = (uint8_t) (len >> 8);
    gs->s_dhcp_tx_buffer[UDP_FRAME_START_INDEX + UDP_ULEN_OFFSET + 1] = (uint8_t) (len & 0xFF);

    //ip_frame_len
    len = len + IP_FRAME_TOTAL_LEN;
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_TLEN_OFFSET] = (uint8_t) (len >> 8);
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_TLEN_OFFSET + 1] = (uint8_t) (len & 0xFF);

    /*calculate checksums - ip mandatory, udp optional*/
    chksm = dhcp_checksum(gs->s_dhcp_tx_buffer, IP_FRAME_START_INDEX, UDP_FRAME_START_INDEX - 1);
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET] = (uint8_t) (chksm >> 8);
    gs->s_dhcp_tx_buffer[IP_FRAME_START_INDEX + IP_CHKSM_OFFSET + 1] = (uint8_t) (chksm & 0xFF);

#ifdef DEBUG
            fprintf(stderr, "dhcp: frame buffer:");
            for (i=0; i<GETAP_DHCP_BUFFER_SIZE; i++){
                if (i % 16 == 0){
                    fprintf(stderr, "\n0x%04x: ",i);
                }
                fprintf(stderr, "%02x ", gs->s_dhcp_tx_buffer[i]);
            }
            fprintf(stderr, "\n");
#endif


   ret = write_frame_fpga(gs, gs->s_dhcp_tx_buffer, GETAP_DHCP_BUFFER_SIZE - 8);   /*leave some headroom for ethernet checksum to be appended by gateware, therefore minus 8*/
   if(ret != 0){
        if(ret > 0){
            log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "dhcp message sent (type %d)", mt);
        }
        else {
            log_message_katcp(gs->s_dispatch, KATCP_LEVEL_ERROR, NULL, "error sending dhcp message type %d", mt);
            return -1;
        }
   }
   return 0;
}

/*this function validates that a received message is a dhcp reply destined for us*/
static int validate_dhcp_reply(struct getap_state *gs){
    uint8_t bootpc[] = {0x00, 0x44};
    uint8_t dhcp_cookie[] = {0x63, 0x82, 0x53, 0x63};
    uint8_t tmp_xid[4];

    tmp_xid[0] = (gs->s_dhcp_xid & 0xFF000000) >> 24;
    tmp_xid[1] = (gs->s_dhcp_xid & 0x00FF0000) >> 16;
    tmp_xid[2] = (gs->s_dhcp_xid & 0x0000FF00) >> 8;
    tmp_xid[3] = (gs->s_dhcp_xid & 0x000000FF);

    if (gs->s_rxb[IP_FRAME_START_INDEX + IP_PROT_OFFSET] != 0x11){                          /*not udp*/
#ifdef DEBUG
    fprintf(stderr, "dhcp: not a udp frame\n");
#endif
        return -1;
    }

    if (memcmp(gs->s_rxb + UDP_FRAME_START_INDEX + UDP_DST_PORT_OFFSET, bootpc, 2) != 0){   /*not port 68*/
#ifdef DEBUG
    fprintf(stderr, "dhcp: not port 68\n");
#endif
        return -1;
    }
    
    if (gs->s_rxb[BOOTP_FRAME_START_INDEX + BOOTP_OPTYPE_OFFSET] != 0x02){                  /*not bootp reply*/
#ifdef DEBUG
    fprintf(stderr, "dhcp: not bootp reply message\n");
#endif
        return -1;
    }

    if (memcmp(gs->s_rxb + BOOTP_FRAME_START_INDEX + BOOTP_MAGIC_COOKIE_OFFSET, dhcp_cookie, 4) != 0){
#ifdef DEBUG
    fprintf(stderr, "dhcp: magic cookie not dhcp\n");
#endif
        return -1;
    }

    if (memcmp(gs->s_rxb + BOOTP_FRAME_START_INDEX + BOOTP_XID_OFFSET, tmp_xid, 4) != 0){
#ifdef DEBUG
    fprintf(stderr, "dhcp: not a valid xid, 0x%x\n", gs->s_dhcp_xid);
#endif
        return -1;
    }
#ifdef DEBUG
    fprintf(stderr, "dhcp: received a valid dhcp message with xid %#x\n", gs->s_dhcp_xid);
#endif
    return 1;   /*valid reply*/
}


static DHCP_MSG_TYPE process_dhcp(struct getap_state *gs){
    int opt_index = 0;
    int opt_end = 0;
    int i;
    DHCP_MSG_TYPE mt;
    char opt;

    //get the offered ip addr
    memcpy(gs->s_dhcp_yip_addr, gs->s_dhcp_rx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_YIPADDR_OFFSET, 4);

#ifdef DEBUG
    fprintf(stderr, "dhcp: received ip address offer of");
    for (i=0; i<4; i++){
        fprintf(stderr, " %d", gs->s_dhcp_yip_addr[i]);
    }
    fprintf(stderr, "\n");
#endif

    //get the server addr
    memcpy(gs->s_dhcp_sip_addr, gs->s_dhcp_rx_buffer + BOOTP_FRAME_START_INDEX + BOOTP_SIPADDR_OFFSET, 4);

#ifdef DEBUG
    fprintf(stderr, "dhcp: server ip address is");
    for (i=0; i<4; i++){
        fprintf(stderr, " %d", gs->s_dhcp_sip_addr[i]);
    }
    fprintf(stderr, "\n");
#endif

    opt_index = DHCP_FRAME_START_INDEX;

    while(opt_end == 0){
        opt = gs->s_dhcp_rx_buffer[opt_index];

        switch(opt){
            case 53:        //message type
                if(gs->s_dhcp_rx_buffer[opt_index + 2] == DHCPOFFER){
                    mt = DHCPOFFER;
                    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "dhcp offer recieved");
#ifdef DEBUG
                    fprintf(stderr, "dhcp: received offer message\n");
#endif
                }
                else if(gs->s_dhcp_rx_buffer[opt_index + 2] == DHCPACK){
                    mt = DHCPACK;
                    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "dhcp ack recieved");
                }
                opt_index = opt_index + 3; 
                break;


            case 1:         //subnet mask
#ifdef DEBUG
                fprintf(stderr, "dhcp: received subnet mask\n");
#endif
                memcpy(gs->s_dhcp_submask, gs->s_dhcp_rx_buffer + opt_index + 2, 4);
                opt_index = opt_index + gs->s_dhcp_rx_buffer[opt_index + 1] + 2;
                break;

            case 3:         //router
#ifdef DEBUG
                fprintf(stderr, "dhcp: received route\n");
#endif
                memcpy(gs->s_dhcp_route, gs->s_dhcp_rx_buffer + opt_index + 2, 4);
                opt_index = opt_index + gs->s_dhcp_rx_buffer[opt_index + 1] + 2;
                break;

            case 255:
#ifdef DEBUG
                    fprintf(stderr, "dhcp: received end option\n");
#endif
                opt_end = 1;
                break;

            default:
                opt_index = opt_index + gs->s_dhcp_rx_buffer[opt_index + 1] + 2;
                break;

        }



printf("opt_index = %d\n", opt_index);


    }


#if 0

    switch(gs->s_dhcp_rx_buffer[DHCP_FRAME_START_INDEX + DHCP_MTYPE_OFFSET + 2]){
        case DHCPOFFER:
#ifdef DEBUG
            fprintf(stderr, "dhcp: received offer message\n");
#endif
            break;

        case DHCPACK:
#ifdef DEBUG
            fprintf(stderr, "dhcp: received ack message\n");
#endif
            break;             

        default:
#ifdef DEBUG
            fprintf(stderr, "dhcp: invalid message\n");
#endif
            break;
    }

#endif

    return mt;
}

/*this command enables the dhcp statemachine which then starts to run on the next run_timer_tap function call*/
int tap_dhcp_cmd(struct katcp_dispatch *d, int argc){
    char *name;
    struct katcp_arb *a;
    struct getap_state *gs;

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
    
    gs->s_dhcp_state = INIT;
    gs->s_dhcp_sm_enable = 1;
    
    return KATCP_RESULT_OK;
}

#define DHCP_RETRIES    5

static int dhcp_statemachine(struct getap_state *gs){
    int retval = 0;
    DHCP_MSG_TYPE mt;
    int subnet; 

    gs->s_dhcp_sm_count++;

    if (gs->s_dhcp_sm_count >= 500){              //after $(count) iterations, something probably went wrong, so take action
        gs->s_dhcp_sm_count = 0;
        if (gs->s_dhcp_sm_retries >= DHCP_RETRIES){
            gs->s_dhcp_sm_retries = 0;
            gs->s_dhcp_sm_enable = 0;   //suspend state machine
        } else {
            gs->s_dhcp_sm_retries++;
            gs->s_dhcp_state = INIT;    //try again
        }
    }

    switch(gs->s_dhcp_state){

        case INIT:
            gs->s_dhcp_valid_dhcp= 0;
#ifdef DEBUG
            if ((gs->s_dhcp_sm_count % 100) == 0){      //reduce spam rate
                fprintf(stderr, "dhcp INIT state\n");
            }
#endif
            retval = dhcp_msg(gs, DHCPDISCOVER);

            if (retval){
                log_message_katcp(gs->s_dispatch, KATCP_LEVEL_ERROR, NULL, "unable to generate dhcp message");
                gs->s_dhcp_state = INIT;
            } else {
                gs->s_dhcp_state = SELECT;
            }
            break;

        case SELECT:
#ifdef DEBUG
            if ((gs->s_dhcp_sm_count % 100) == 0){
                fprintf(stderr, "dhcp SELECT state\n");
            }
#endif

            if (gs->s_dhcp_valid_dhcp == 1){
                gs->s_dhcp_valid_dhcp = 0; 
                mt = process_dhcp(gs);
                if (mt == DHCPOFFER){
                    retval = dhcp_msg(gs, DHCPREQUEST);
                    if (retval){
                        log_message_katcp(gs->s_dispatch, KATCP_LEVEL_ERROR, NULL, "unable to generate dhcp message");
                        gs->s_dhcp_state = SELECT;

                    } else {
                        gs->s_dhcp_state = REQUEST;
                    }
                }
            }

            break;

        case REQUEST:
#ifdef DEBUG
            if ((gs->s_dhcp_sm_count % 100) == 0){
                fprintf(stderr, "dhcp REQUEST state\n");
            }
#endif
            if (gs->s_dhcp_valid_dhcp == 1){
                gs->s_dhcp_valid_dhcp = 0;
                mt = process_dhcp(gs);
                if (mt == DHCPACK){

                    subnet = dhcp_convert_netmask(gs);

                    snprintf(gs->s_address_name, GETAP_IP_BUFFER, "%d.%d.%d.%d/%d", gs->s_dhcp_yip_addr[0], gs->s_dhcp_yip_addr[1], gs->s_dhcp_yip_addr[2], gs->s_dhcp_yip_addr[3], subnet);
                    snprintf(gs->s_gateway_name, GETAP_IP_BUFFER, "%d.%d.%d.%d", gs->s_dhcp_route[0], gs->s_dhcp_route[1], gs->s_dhcp_route[2], gs->s_dhcp_route[3]);
#ifdef DEBUG
                    fprintf(stderr, "dhcp: ip/mask is %s\n", gs->s_address_name);
                    fprintf(stderr, "dhcp: route is %s\n", gs->s_gateway_name);
#endif

#if 0
                    for (i=0; i<4; i++){
                        gs->s_address_binary = gs->s_dhcp_yip_addr[i];
                        gs->s_address_binary = gs->s_adress_binary << ((3-i)*8);
                    }
                    for (i=0; i<4; i++){
                        gs->s_mask_binary = gs->s_dhcp_submask[i];
                        gs->s_mask_binary = gs->s_mask_binary << ((3-i)*8);
                    }
#endif

                    if(configure_ip_fpga(gs) < 0){
                        log_message_katcp(gs->s_dispatch, KATCP_LEVEL_ERROR, NULL, "unable to make requested changes for %s", gs->s_tap_name);
                        gs->s_dhcp_state = REQUEST;
                    } else {
                        tap_reload_arp(gs->s_dispatch, gs);
                        announce_arp(gs);
                        gs->s_dhcp_state = BOUND;
                    }
                    
#if 0
                    retval = dhcp_configure_if(gs);
                    if (retval){
                        log_message_katcp(gs->s_dispatch, KATCP_LEVEL_ERROR, NULL, "unable to configure interface");
                        gs->s_dhcp_state = REQUEST;

                    } else {
                        gs->s_dhcp_state = BOUND;
                    }
#endif

                }
            }
            
            break;

        case BOUND:
            gs->s_dhcp_sm_enable = 0;

            break;

        default:
            gs->s_dhcp_sm_enable = 0;
            gs->s_dhcp_state = INIT;
            break;

    }

    return retval;
}

static int dhcp_configure_if(struct getap_state *gs){

    log_message_katcp(gs->s_dispatch, KATCP_LEVEL_INFO, NULL, "configuring interface %s",gs->s_tap_name );
    return 0;
}


static int dhcp_convert_netmask(struct getap_state *gs){
    unsigned int count=0;
    unsigned char temp;
    int i,j;

    for (i=0; i<4; i++){
        temp = gs->s_dhcp_submask[i];
        for (j=0; j<8; j++){
            if ((temp & 1) == 1){
                count++;
            }
            temp = temp >> 1;
        }
    }

    return count;
}
#undef DEBUG
