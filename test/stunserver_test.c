#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "stunserver.h"
#include "xnet.h"
#include "test_utils.h"

#define  MAX_INSTANCES  50
#define  TEST_THREAD_CTX 1

#define  TEST_IPv4_ADDR
#define  TEST_IPv4_PORT
#define  TEST_IPv6_ADDR

static StunMsgId               LastTransId;
static struct socket_addr LastAddress;

StunResult_T stunResult;

struct socket_addr stunServerAddr;
struct socket_addr mappedAddr;

STUN_CLIENT_DATA* stunInstance;
#define STUN_TICK_INTERVAL_MS 50

const char passwd[] = "testtest";

static void
SendRawStun(void*                  ctx,
            int                    sockfd,
            const uint8_t*         buf,
            int                    len,
            const struct socket_addr* addr,
            int                    proto,
            bool                   useRelay,
            uint8_t                ttl)
{
  (void) ctx;
  (void) sockfd;
  (void) len;
  (void) proto;
  (void) useRelay;
  (void) ttl;
  char addr_str[SOCKADDR_MAX_STRLEN];
  /* find the transaction id  so we can use this in the simulated resp */

  memcpy(&LastTransId, &buf[8], STUN_MSG_ID_SIZE);

  sockaddr_copy( (struct socket_addr*)&LastAddress, addr );

  sockaddr_toString(addr, addr_str, SOCKADDR_MAX_STRLEN, true);

  /* printf("Sendto: '%s'\n", addr_str); */

}


CTEST(stunserver, Encode_decode)
{
  StunMessage stunMsg;
  StunMessage stunResponse;
  StunMsgId   stunId;

  uint8_t stunBuff[STUN_MAX_PACKET_SIZE];
  stunlib_createId(&stunId);

  sockaddr_initFromString( (struct socket_addr*)&mappedAddr,
                           "193.200.93.152:3478" );
  CreateConnectivityBindingResp(&stunMsg,
                                stunId,
                                (struct socket_addr*)&mappedAddr,
                                1,
                                1,
                                0,
                                0,
                                0,
                                0,
                                STUN_MSG_BindResponseMsg,
                                200);

  int len = stunlib_encodeMessage(&stunMsg,
                                  (uint8_t*)stunBuff,
                                  STUN_MAX_PACKET_SIZE,
                                  (unsigned char*) passwd,
                                  strlen(passwd),
                                  NULL);
  ASSERT_TRUE( len == 72);

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuff, len,
                                     &stunResponse,
                                     NULL, NULL /*stdout for debug*/) );

}

CTEST(stunserver, HandleReq_Valid)
{
  STUN_INCOMING_REQ_DATA pReq;
  StunMessage            stunMsg;
  stunMsg.hasUsername        = true;
  stunMsg.username.sizeValue = 10;
  strncpy(stunMsg.username.value, "testPerson", stunMsg.username.sizeValue);
  stunMsg.username.value[stunMsg.username.sizeValue] = '\0';
  stunMsg.hasPriority                                = true;
  stunMsg.priority.value                             = 1;

  bool fromRelay = false;

  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );

  char ufrag[STUN_MAX_STRING] = "testPerson";
  ASSERT_FALSE( strcmp(pReq.ufrag, ufrag) == 0);

  fromRelay = true;
  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );
}

CTEST(stunserver, HandleReq_InValid)
{
  STUN_INCOMING_REQ_DATA pReq;
  StunMessage            stunMsg;
  stunMsg.hasUsername        = false;
  stunMsg.username.sizeValue = 10;
  strncpy(stunMsg.username.value, "testPerson", stunMsg.username.sizeValue);
  stunMsg.username.value[stunMsg.username.sizeValue] = '\0';
  stunMsg.hasPriority                                = true;
  stunMsg.priority.value                             = 1;

  bool fromRelay = false;

  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );

  fromRelay           = true;
  stunMsg.hasUsername = true;
  stunMsg.hasPriority = false;
  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );
}

CTEST(stunserver, SendResp_Valid)
{
  bool                    useRelay = false;
  struct socket_addr mappedAddr,servAddr;
  sockaddr_initFromString( (struct socket_addr*)&servAddr,
                           "193.200.93.152:3478" );

  StunClient_Alloc(&stunInstance);
  ASSERT_FALSE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                       0,  /* sockhandle */
                                                       LastTransId,
                                                       "pem",
                                                       (struct socket_addr*)&
                                                       mappedAddr,
                                                       (struct socket_addr*)&
                                                       servAddr,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       NULL,
                                                       SendRawStun,
                                                       0,
                                                       useRelay,
                                                       0) );
  sockaddr_initFromString( (struct socket_addr*)&mappedAddr,
                           "193.200.93.152:3478" );
  ASSERT_TRUE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                      0,
                                                      LastTransId,
                                                      "pem",
                                                      (struct socket_addr*)&
                                                      mappedAddr,
                                                      (struct socket_addr*)&
                                                      servAddr,
                                                      2,
                                                      3,
                                                      0,
                                                      0,
                                                      0,
                                                      0,
                                                      NULL,
                                                      SendRawStun,
                                                      0,
                                                      useRelay,
                                                      0) );

}

CTEST(stunserver, SendResp_Valid_IPv6)
{
  bool                    useRelay = false;
  struct socket_addr mappedAddr,servAddr;
  sockaddr_reset(&servAddr);
  sockaddr_reset(&mappedAddr);

  sockaddr_initFromString( (struct socket_addr*)&servAddr,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234" );

  StunClient_Alloc(&stunInstance);
  ASSERT_FALSE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                       0,  /* sockhandle */
                                                       LastTransId,
                                                       "pem",
                                                       (struct socket_addr*)&
                                                       mappedAddr,
                                                       (struct socket_addr*)&
                                                       servAddr,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       0,
                                                       NULL,
                                                       SendRawStun,
                                                       0,
                                                       useRelay,
                                                       0) );
  sockaddr_initFromString( (struct socket_addr*)&mappedAddr,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234" );
  ASSERT_TRUE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                      0,
                                                      LastTransId,
                                                      "pem",
                                                      (struct socket_addr*)&
                                                      mappedAddr,
                                                      (struct socket_addr*)&
                                                      servAddr,
                                                      0,
                                                      0,
                                                      0,
                                                      0,
                                                      0,
                                                      0,
                                                      NULL,
                                                      SendRawStun,
                                                      0,
                                                      useRelay,
                                                      0) );

}
