
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "turnclient.h"
#include "turn_intern.h"
#include "xnet.h"
#include "test_utils.h"

#define  MAX_INSTANCES  5
#define  TEST_THREAD_CTX 1



/* static TurnCallBackData_T TurnCbData[MAX_INSTANCES]; */

/* static int            TestNo; */
/* static uint32_t StunDefaultTimeoutList[STUNCLIENT_MAX_RETRANSMITS */
/* ] = {100, 0}; */
static StunMsgId               LastTransId;
static struct socket_addr LastAddress;


static bool runningAsIPv6;

static const uint8_t StunCookie[] = STUN_MAGIC_COOKIE_ARRAY;

TurnResult_T       turnResult;
TurnCallBackData_T latestResult;
uint8_t            latestBuf[1600];
size_t             latestBufLen;

struct socket_addr turnServerAddr;
TURN_INSTANCE_DATA*     pInst;


static void
TurnStatusCallBack(void*               ctx,
                   TurnCallBackData_T* retData)
{
  (void) ctx;
  turnResult = retData->turnResult;
  memcpy(&latestResult, retData, sizeof latestResult);
  /* printf("Got TURN status callback (Result (%i)\n", retData->turnResult); */

}


static void
SendRawStun(const uint8_t*         buf,
            size_t                 len,
            const struct socket_addr* addr,
            void*                  ctx)
{
  (void) ctx;
  (void) len;
/*  char addr_str[SOCKADDR_MAX_STRLEN]; */
/* find the transaction id  so we can use this in the simulated resp */


  memcpy(&LastTransId, &buf[8], STUN_MSG_ID_SIZE);

  sockaddr_copy( (struct socket_addr*)&LastAddress, addr );
  if (len < sizeof latestBuf)
  {
    memcpy(latestBuf, buf, len);
  }
  latestBufLen = len;

  /* sockaddr_toString(addr, addr_str, SOCKADDR_MAX_STRLEN, true); */

  /* printf("TurnClienttest sendto: '%s'\n", addr_str); */

}

static int
StartAllocateTransaction()
{
  runningAsIPv6 = false;
  sockaddr_initFromString( (struct socket_addr*)&turnServerAddr,
                           "158.38.48.10:3478" );
  /* kick off turn */
  return TurnClient_StartAllocateTransaction(&pInst,
                                             50,
                                             NULL,
                                             "test",
                                             NULL,
                                             (struct socket_addr*)&turnServerAddr,
                                             "pem",
                                             "pem",
                                             0,
                                             SendRawStun,
                                             TurnStatusCallBack,
                                             false,
                                             0);

}

static int
StartAllocateTransaction_IPv6()
{
  struct socket_addr addr;
  sockaddr_initFromString( (struct socket_addr*)&addr,"158.38.48.10:3478" );
  runningAsIPv6 = true;
  /* kick off turn */
  return TurnClient_StartAllocateTransaction(&pInst,
                                             50,
                                             NULL,
                                             "test",
                                             NULL,
                                             (struct socket_addr*)&addr,
                                             "pem",
                                             "pem",
                                             AF_INET6,
                                             SendRawStun,
                                             TurnStatusCallBack,
                                             false,
                                             0);

}


static int
StartSSODAAllocateTransaction()
{
  sockaddr_initFromString( (struct socket_addr*)&turnServerAddr,
                           "158.38.v8.10:3478" );

  /* kick off turn */
  return TurnClient_StartAllocateTransaction(&pInst,
                                             50,
                                             NULL,
                                             "test",
                                             NULL,
                                             (struct socket_addr*)&turnServerAddr,
                                             "pem",
                                             "pem",
                                             AF_INET + AF_INET6,
                                             SendRawStun,               /* send
                                                                         * func
                                                                         **/
                                             TurnStatusCallBack,
                                             false,
                                             0);

}

static void
SimAllocResp(int  ctx,
             bool relay,
             bool xorMappedAddr,
             bool lifetime,
             bool IPv6,
             bool duplicate,
             bool wrongTransId)
{
  (void) ctx;
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  if (wrongTransId)
  {
    memcpy(&m.msgHdr.id, &LastTransId + 8, STUN_MSG_ID_SIZE);
  }
  else
  {
    memcpy(&m.msgHdr.id, &LastTransId, STUN_MSG_ID_SIZE);
  }
  memcpy( &m.msgHdr.cookie, StunCookie, sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType = STUN_MSG_AllocateResponseMsg;

  /* relay */
  if (relay)
  {
    if (IPv6)
    {
      uint8_t addr[16] =
      {0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x0, 0x2, 0x2, 0x26, 0x18, 0xff, 0xfe,
       0x92, 0x6d, 0x53};
      m.hasXorRelayAddressIPv6 = true;
      stunlib_setIP6Address(&m.xorRelayAddressIPv6, addr, 0x4200);


    }
    else
    {
      m.hasXorRelayAddressIPv4           = true;
      m.xorRelayAddressIPv4.familyType   = STUN_ADDR_IPv4Family;
      m.xorRelayAddressIPv4.addr.v4.addr = 3251135384UL;      /*
                                                               *
                                                               *"193.200.99.152"
                                                               **/
      m.xorRelayAddressIPv4.addr.v4.port = 42000;
    }
  }

  /* XOR mapped addr*/
  if (xorMappedAddr)
  {
    if (IPv6)
    {
      uint8_t addr[16] =
      {0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x1, 0x22, 0x21, 0x26, 0x18, 0xff,
       0xfe, 0x92, 0x6d, 0x53};
      m.hasXorMappedAddress = true;
      stunlib_setIP6Address(&m.xorMappedAddress, addr, 0x4200);

    }
    else
    {

      m.hasXorMappedAddress           = true;
      m.xorMappedAddress.familyType   = STUN_ADDR_IPv4Family;
      m.xorMappedAddress.addr.v4.addr = 1009527574UL;      /* "60.44.43.22"); */
      m.xorMappedAddress.addr.v4.port = 43000;
    }
  }

  /* lifetime */
  if (lifetime)
  {
    m.hasLifetime    = true;
    m.lifetime.value = 60;
  }

  TurnClient_HandleIncResp(pInst, &m, NULL);

  if (duplicate)
  {
    TurnClient_HandleIncResp(pInst, &m, NULL);
  }

}

static void
SimSSODAAllocResp(int  ctx,
                  bool relay,
                  bool xorMappedAddr,
                  bool lifetime)
{
  (void) ctx;
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType = STUN_MSG_AllocateResponseMsg;

  /* relay */
  if (relay)
  {
    uint8_t addr[16] =
    {0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x0, 0x2, 0x2, 0x26, 0x18, 0xff, 0xfe,
     0x92, 0x6d, 0x53};
    m.hasXorRelayAddressIPv6 = true;
    stunlib_setIP6Address(&m.xorRelayAddressIPv6, addr, 0x4200);

    m.hasXorRelayAddressIPv4           = true;
    m.xorRelayAddressIPv4.familyType   = STUN_ADDR_IPv4Family;
    m.xorRelayAddressIPv4.addr.v4.addr = 3251135384UL;    /* "193.200.99.152" */
    m.xorRelayAddressIPv4.addr.v4.port = 42000;

    m.hasXorRelayAddressSSODA = true;
  }

  /* XOR mapped addr*/
  if (xorMappedAddr)
  {

    m.hasXorMappedAddress           = true;
    m.xorMappedAddress.familyType   = STUN_ADDR_IPv4Family;
    m.xorMappedAddress.addr.v4.addr = 1009527574UL;    /* "60.44.43.22"); */
    m.xorMappedAddress.addr.v4.port = 43000;

  }

  /* lifetime */
  if (lifetime)
  {
    m.hasLifetime    = true;
    m.lifetime.value = 60;
  }

  TurnClient_HandleIncResp(pInst, &m, NULL);

}

static void
Sim_ChanBindOrPermissionResp(int      ctx,
                             uint16_t msgType,
                             uint32_t errClass,
                             uint32_t errNumber)
{
  (void) ctx;
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType = msgType;

  if ( (msgType == STUN_MSG_ChannelBindErrorResponseMsg)
       || (msgType == STUN_MSG_CreatePermissionErrorResponseMsg) )
  {
    m.hasErrorCode         = true;
    m.errorCode.errorClass = errClass;
    m.errorCode.number     = errNumber;
  }
  TurnClient_HandleIncResp(pInst, &m, NULL);
}


static void
SimInitialAllocRespErr(int      ctx,
                       bool     hasErrCode,
                       uint32_t errClass,
                       uint32_t errNumber,
                       bool     hasRealm,
                       bool     hasNonce,
                       bool     hasAltServer)
{
  (void) ctx;
  StunMessage m;

  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType = STUN_MSG_AllocateErrorResponseMsg;

  /* error code */
  if (hasErrCode)
  {
    m.hasErrorCode         = hasErrCode;
    m.errorCode.errorClass = errClass;
    m.errorCode.number     = errNumber;
  }

  /* realm */
  if (hasRealm)
  {
    m.hasRealm = hasRealm;
    strncpy( m.realm.value, "united.no", strlen("united.no") );
    m.realm.sizeValue = strlen(m.realm.value);
  }

  /* nonce */
  if (hasNonce)
  {
    m.hasNonce = hasNonce;
    strncpy( m.nonce.value, "mydaftnonce", strlen("mydaftnonce") );
    m.nonce.sizeValue = strlen(m.nonce.value);
  }


  /* alternate server */
  if (hasAltServer)
  {
    m.hasAlternateServer = true;
    if (runningAsIPv6)
    {
      uint8_t addr[16] =
      {0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x0, 0x2, 0x2, 0x26, 0x18, 0xff, 0xfe,
       0x92, 0x6d, 0x53};
      stunlib_setIP6Address(&m.alternateServer, addr, 0x4200);


    }
    else
    {

      m.alternateServer.familyType   = STUN_ADDR_IPv4Family;
      m.alternateServer.addr.v4.addr = 0x12345678;
      m.alternateServer.addr.v4.port = 3478;
    }
  }


  TurnClient_HandleIncResp(pInst, &m, NULL);
}



static void
Sim_RefreshResp(int ctx)
{
  (void) ctx;
  TurnClientSimulateSig(pInst, TURN_SIGNAL_RefreshResp);
}


/* allocation refresh error */
static void
Sim_RefreshError(int      ctx,
                 uint32_t errClass,
                 uint32_t errNumber,
                 bool     hasRealm,
                 bool     hasNonce)
{
  (void) ctx;
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType       = STUN_MSG_RefreshErrorResponseMsg;
  m.hasErrorCode         = true;
  m.errorCode.errorClass = errClass;
  m.errorCode.number     = errNumber;

  /* realm */
  if (hasRealm)
  {
    m.hasRealm = hasRealm;
    strncpy( m.realm.value, "united.no", strlen("united.no") );
    m.realm.sizeValue = strlen(m.realm.value);
  }

  /* nonce */
  if (hasNonce)
  {
    m.hasNonce = hasNonce;
    strncpy( m.nonce.value, "mydaftnonce", strlen("mydaftnonce") );
    m.nonce.sizeValue = strlen(m.nonce.value);
  }

  TurnClient_HandleIncResp(pInst, &m, NULL);
}


static int
GotoAllocatedState(int appCtx)
{
  int ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(appCtx, true, 4, 1, true, true, false);   /* 401, has
                                                                    * realm has
                                                                    * nonce */
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  return ctx;
}

static int
GotoAllocatedState_IPv6(int appCtx)
{
  int ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(appCtx, true, 4, 1, true, true, false);   /* 401, has
                                                                    * realm has
                                                                    * nonce */
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  return ctx;
}



static void
Sim_TimerRefreshAlloc(int ctx)
{
  (void) ctx;
  TurnClientSimulateSig(pInst, TURN_SIGNAL_TimerRefreshAlloc);
}

static void
Sim_TimerRefreshChannelBind(int ctx)
{
  (void) ctx;
  TurnClientSimulateSig(pInst, TURN_SIGNAL_TimerRefreshChannel);
}

static void
Sim_TimerRefreshPermission(int ctx)
{
  (void) ctx;
  TurnClientSimulateSig(pInst, TURN_SIGNAL_TimerRefreshPermission);
}

CTEST(turnclient, WaitAllocRespNotAut_Timeout)
{
  StartAllocateTransaction();

  /* 1 Tick */
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE( turnResult == TurnResult_Empty);
  ASSERT_TRUE( sockaddr_alike( (struct socket_addr*)&LastAddress,
                               (struct socket_addr*)&turnServerAddr ) );
  /* 2 Tick */
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_Empty);

  /* 3 Tick */
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_Empty);

  /* 4 Tick */
  {
    int i;
    for (i = 0; i < 100; i++)
    {
      TurnClient_HandleTick(pInst);
    }
  }
  ASSERT_TRUE(turnResult == TurnResult_AllocFailNoAnswer);

}


CTEST(turnclient, startAllocation_NULL)
{
  ASSERT_FALSE( TurnClient_StartAllocateTransaction(NULL,
                                                    50,
                                                    NULL,
                                                    "test",
                                                    NULL,
                                                    NULL,
                                                    "pem",
                                                    "pem",
                                                    AF_INET6,
                                                    SendRawStun,
                                                    TurnStatusCallBack,
                                                    false,
                                                    0) );

}


CTEST(turnclient, startAllocation_even)
{
  ASSERT_TRUE( TurnClient_StartAllocateTransaction(&pInst,
                                                   50,
                                                   NULL,
                                                   "test",
                                                   NULL,
                                                   NULL,
                                                   "pem",
                                                   "pem",
                                                   AF_INET6,
                                                   SendRawStun,
                                                   TurnStatusCallBack,
                                                   true,
                                                   0) );

}

CTEST(turnclient, startAllocation_odd)
{
  ASSERT_TRUE( TurnClient_StartAllocateTransaction(&pInst,
                                                   50,
                                                   NULL,
                                                   "test",
                                                   NULL,
                                                   NULL,
                                                   "pem",
                                                   "pem",
                                                   AF_INET6,
                                                   SendRawStun,
                                                   TurnStatusCallBack,
                                                   true,
                                                   45678) );

}

CTEST(tunrclient, resultToString)
{
  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_AllocOk),
                     "TurnResult_AllocOk") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_AllocFail),
                     "TurnResult_AllocFail") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_AllocFailNoAnswer),
                     "TurnResult_AllocFailNoAnswer") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_AllocUnauthorised),
                     "TurnResult_AllocUnauthorised") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_CreatePermissionOk),
                     "TurnResult_CreatePermissionOk") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_CreatePermissionFail),
                     "TurnResult_CreatePermissionFail") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_CreatePermissionNoAnswer),
                     "TurnResult_CreatePermissionNoAnswer") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_CreatePermissionQuotaReached),
                     "TurnResult_CreatePermissionQuotaReached") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_PermissionRefreshFail),
                     "TurnResult_PermissionRefreshFail") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_ChanBindOk),
                     "TurnResult_ChanBindOk") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_ChanBindFail),
                     "TurnResult_ChanBindFail") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_ChanBindFailNoanswer),
                     "TurnResult_ChanBindFailNoanswer") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_RefreshFail),
                     "TurnResult_RefreshFail") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_RefreshFailNoAnswer),
                     "TurnResult_RefreshFailNoAnswer") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_RelayReleaseComplete),
                     "TurnResult_RelayReleaseComplete") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_RelayReleaseFailed),
                     "TurnResult_RelayReleaseFailed") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_InternalError),
                     "TurnResult_InternalError") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_MalformedRespWaitAlloc),
                     "TurnResult_MalformedRespWaitAlloc") == 0);

  ASSERT_TRUE(strcmp(TurnResultToStr(TurnResult_Empty),
                     "unknown turnresult ??") == 0);
}

CTEST(turnclient, WaitAllocRespNotAut_AllocRspOk)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, true, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);
  ASSERT_FALSE( TurnClient_hasBeenRedirected(pInst) );
  ASSERT_FALSE( TurnClient_hasBeenRedirected(NULL) );

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}

CTEST(turnclient, WaitAllocRespNotAut_AllocRspDuplicate)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, true, true);
  ASSERT_FALSE( turnResult == TurnResult_AllocOk);
  ASSERT_FALSE( TurnClient_hasBeenRedirected(pInst) );

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}

CTEST(turnclient, WaitAllocRespNotAut_AllocRspOk_IPv6)
{
  int ctx;
  ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, true, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);
  ASSERT_FALSE( TurnClient_hasBeenRedirected(pInst) );

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}

CTEST(turnclient, WaitAllocRespNotAutSSODA_AllocRspOk)
{
  int                     ctx;
  struct socket_addr relayIPv4;
  struct socket_addr relayIPv6;
  sockaddr_initFromString( (struct socket_addr*)&relayIPv4,
                           "193.200.99.152:42000" );
  sockaddr_initFromString( (struct socket_addr*)&relayIPv6,
                           "[2001:470:dc88:2:226:18ff:fe92:6d53]:16896" );

  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimSSODAAllocResp(ctx, true, true, true);
  ASSERT_TRUE( turnResult == TurnResult_AllocOk);

  ASSERT_TRUE( sockaddr_alike( (struct socket_addr*)&latestResult.TurnResultData.
                               AllocResp.relAddrIPv4,
                               (struct socket_addr*)&relayIPv4 ) );
  ASSERT_TRUE( sockaddr_alike( (struct socket_addr*)&latestResult.TurnResultData.
                               AllocResp.relAddrIPv6,
                               (struct socket_addr*)&relayIPv6 ) );
  ASSERT_FALSE( sockaddr_alike( (struct socket_addr*)&latestResult.TurnResultData.
                                AllocResp.relAddrIPv4,
                                (struct socket_addr*)&relayIPv6 ) );

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}

CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_AltServer)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 3, 0, false, false, true);    /* 300, alt
                                                                  * server */
  ASSERT_FALSE(turnResult == TurnResult_Empty);

  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);   /* 401, has
                                                                 * realm and
                                                                 * nonce */
  ASSERT_FALSE(turnResult == TurnResult_Empty);

  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  ASSERT_TRUE( turnResult == TurnResult_AllocOk);

  ASSERT_TRUE( TurnClient_hasBeenRedirected(pInst) );
  ASSERT_TRUE( sockaddr_alike( (struct socket_addr*)&LastAddress,
                               TurnClient_getRedirectedServerAddr(pInst) ) );

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}

CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_AltServer_IPv6)
{
  int ctx;
  ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 3, 0, false, true, true);    /* 300, alt
                                                                 * server */
  ASSERT_FALSE(turnResult == TurnResult_Empty);

  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);   /* 401, has
                                                                 * realm and
                                                                 * nonce */
  ASSERT_FALSE(turnResult == TurnResult_Empty);

  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  ASSERT_TRUE( turnResult == TurnResult_AllocOk);

  ASSERT_TRUE( TurnClient_hasBeenRedirected(pInst) );
  ASSERT_TRUE( sockaddr_alike( (struct socket_addr*)&LastAddress,
                               TurnClient_getRedirectedServerAddr(pInst) ) );

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}



CTEST(turnclient, WaitAllocRespNotAut_AllocRsp_Malf1)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, false, true, true, runningAsIPv6, false, false);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);

}



CTEST(turnclient, WaitAllocRespNotAut_AllocRsp_Malf2)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, false, true, runningAsIPv6, false, false);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);

}



CTEST(turnclient, WaitAllocRespNotAut_AllocRsp_Malf3)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, false, runningAsIPv6, false, false);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);

}



CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_Ok)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);   /* 401, has
                                                                 * realm and
                                                                 * nonce */
  ASSERT_FALSE(turnResult == TurnResult_Empty);

  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);
  ASSERT_FALSE( TurnClient_hasBeenRedirected(pInst) );
  ASSERT_FALSE( sockaddr_alike( (struct socket_addr*)&LastAddress,
                                TurnClient_getRedirectedServerAddr(pInst) ) );
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_Ok_IPv6)
{
  int ctx;
  ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);   /* 401, has
                                                                 * realm and
                                                                 * nonce */
  ASSERT_FALSE(turnResult == TurnResult_Empty);

  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);
  ASSERT_FALSE( TurnClient_hasBeenRedirected(pInst) );
  ASSERT_FALSE( sockaddr_alike( (struct socket_addr*)&LastAddress,
                                TurnClient_getRedirectedServerAddr(pInst) ) );
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}



CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_ErrNot401)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 4, false, false, false);   /* 404, no
                                                                  * realm, no
                                                                  * nonce */
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);
}

CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_ErrNot401_IPv6)
{
  int ctx;
  ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 4, false, runningAsIPv6, false);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);
}



CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_Err_malf1)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, false, true, false);   /* 401, no
                                                                  * realm, nonce
                                                                  **/
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);
}


CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_Err_malf2)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, false, false);   /* 401, realm,
                                                                  * no nonce */
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);

}



CTEST(turnclient, WaitAllocRespNotAut_AllocRspErr_Err_malf3)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 3, 0, false, false, false);    /* 300,
                                                                    * missing
                                                                    * alt
                                                                    * server */
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_MalformedRespWaitAlloc);
  TurnClient_Deallocate(pInst);

}


CTEST(turnclient, WaitAllocResp_AllocRespOk)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);   /* 401, has
                                                                 * realm and
                                                                 * nonce */
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
  TurnClient_free(pInst);

}

CTEST(turnclient, WaitAllocResp_AllocRespOk_IPv6)
{
  int ctx;
  ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);   /* 401, has
                                                                 * realm and
                                                                 * nonce */
  TurnClient_HandleTick(pInst);
  SimAllocResp(ctx, true, true, true, runningAsIPv6, false, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
  TurnClient_free(pInst);

}


CTEST(turnclient, WaitAllocResp_SSODA_AllocRespOk)
{
  int ctx;
  ctx = StartSSODAAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);   /* 401, has
                                                                 * realm and
                                                                 * nonce */
  TurnClient_HandleTick(pInst);
  /* SimAllocResp(ctx, true, true, true, runningAsIPv6); */
  SimSSODAAllocResp(ctx, true, true, true);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}



CTEST(turnclient, WaitAllocResp_AllocRespErr)
{
  int ctx;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);
  ASSERT_FALSE(turnResult == TurnResult_Empty);
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 4, false, false, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocUnauthorised);
  TurnClient_Deallocate(pInst);
}

CTEST(turnclient, WaitAllocResp_AllocRespErr_IPv6)
{
  int ctx;
  ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);
  ASSERT_FALSE(turnResult == TurnResult_Empty);
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 4, false, false, false);
  ASSERT_TRUE(turnResult == TurnResult_AllocUnauthorised);
  TurnClient_Deallocate(pInst);
}



CTEST(turnclient, WaitAllocResp_Retry)
{
  int ctx, i;
  ctx = StartAllocateTransaction();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);      /* 401, has
                                                                    * realm and
                                                                    * nonce */
  ASSERT_FALSE(turnResult == TurnResult_Empty);
  for (i = 0; i < 100; i++)
  {
    TurnClient_HandleTick(pInst);
  }

  ASSERT_TRUE(turnResult == TurnResult_AllocFailNoAnswer);

  TurnClient_Deallocate(pInst);
}

CTEST(turnclient, WaitAllocResp_Retry_IPv6)
{
  int ctx, i;
  ctx = StartAllocateTransaction_IPv6();
  TurnClient_HandleTick(pInst);
  SimInitialAllocRespErr(ctx, true, 4, 1, true, true, false);      /* 401, has
                                                                    * realm and
                                                                    * nonce */
  ASSERT_FALSE(turnResult == TurnResult_Empty);
  for (i = 0; i < 100; i++)
  {
    TurnClient_HandleTick(pInst);
  }

  ASSERT_TRUE(turnResult == TurnResult_AllocFailNoAnswer);

  TurnClient_Deallocate(pInst);
}


CTEST(turnclient, Allocated_RefreshOk)
{
  int ctx, i;

  ctx = GotoAllocatedState(9);

  for (i = 0; i < 2; i++)
  {
    Sim_TimerRefreshAlloc(ctx);
    TurnClient_HandleTick(pInst);
    Sim_RefreshResp(ctx);
  }
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_RefreshOk_IPv6)
{
  int ctx, i;

  ctx = GotoAllocatedState_IPv6(9);

  for (i = 0; i < 2; i++)
  {
    Sim_TimerRefreshAlloc(ctx);
    TurnClient_HandleTick(pInst);
    Sim_RefreshResp(ctx);
  }
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient, Allocated_RefreshError)
{
  int ctx;
  ctx = GotoAllocatedState(4);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshError(ctx, 4, 1, false, false);
  ASSERT_TRUE(turnResult == TurnResult_RefreshFail);

}

CTEST(turnclient, Allocated_RefreshError_IPv6)
{
  int ctx;
  ctx = GotoAllocatedState_IPv6(4);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshError(ctx, 4, 1, false, false);
  ASSERT_TRUE(turnResult == TurnResult_RefreshFail);

}



CTEST(turnclient, Allocated_StaleNonce)
{
  int ctx;
  ctx = GotoAllocatedState(4);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshResp(ctx);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshError(ctx, 4, 38, true, true);   /* stale nonce */

  TurnClient_HandleTick(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_StaleNonce_IPv6)
{
  int ctx;
  ctx = GotoAllocatedState_IPv6(4);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshResp(ctx);

  Sim_TimerRefreshAlloc(ctx);
  TurnClient_HandleTick(pInst);
  Sim_RefreshError(ctx, 4, 38, true, true);   /* stale nonce */

  TurnClient_HandleTick(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_AllocOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_ChanBindReqOk)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  ASSERT_TRUE( TurnClient_StartChannelBindReq(pInst, 0x4001,
                                              (struct socket_addr*)&peerIp) );
  ASSERT_FALSE( TurnClient_StartChannelBindReq(pInst, 0x4001,
                                               (struct socket_addr*)&peerIp) );
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_TRUE(stats.channelBound);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}

CTEST(turnclient, Allocated_ChanBindReqOk_IPv6)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234" );

  ctx = GotoAllocatedState_IPv6(12);
  ASSERT_TRUE( TurnClient_StartChannelBindReq(pInst, 0x4001,
                                              (struct socket_addr*)&peerIp) );
  ASSERT_FALSE( TurnClient_StartChannelBindReq(pInst, 0x4001,
                                               (struct socket_addr*)&peerIp) );
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_TRUE(stats.channelBound);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);

}

CTEST(turnclient, Allocated_ChanBindReq_fail_num)
{
  struct socket_addr peerIp;
  int                     ctx;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  ASSERT_FALSE( TurnClient_StartChannelBindReq(pInst, 0x3001,
                                               (struct socket_addr*)&peerIp) );

  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_FALSE(turnResult == TurnResult_ChanBindOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_ChanBindReq_fail_ip)
{
  struct socket_addr peerIp;
  int                     ctx;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  ASSERT_FALSE( TurnClient_StartChannelBindReq(pInst, 0x4001,
                                               (struct socket_addr*)NULL) );

  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_FALSE(turnResult == TurnResult_ChanBindOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_ChanBindRefresh)
{
  struct socket_addr peerIp;
  int                     ctx;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  /* verfiy callback is not called again */
  turnResult = TurnResult_Empty;
  Sim_TimerRefreshChannelBind(ctx);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  ASSERT_TRUE(turnResult == TurnResult_Empty);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_ChanBindRefresh_IPv6)
{
  struct socket_addr peerIp;
  int                     ctx;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234" );

  ctx = GotoAllocatedState_IPv6(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  /* verfiy callback is not called again */
  turnResult = TurnResult_Empty;
  Sim_TimerRefreshChannelBind(ctx);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  ASSERT_TRUE(turnResult == TurnResult_Empty);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}



CTEST(turnclient, Allocated_ChanBindErr)
{
  struct socket_addr peerIp;
  int                     ctx;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindErrorResponseMsg, 4, 4);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindFail);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_ChanBindErr_IPv6)
{
  struct socket_addr peerIp;
  int                     ctx;
  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234" );

  ctx = GotoAllocatedState_IPv6(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindErrorResponseMsg, 4, 4);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindFail);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient, Allocated_CreatePermissionReqOk)
{
  struct socket_addr  peerIp[6];
  struct socket_addr* p_peerIp[6];
  int                      ctx;
  uint32_t                 i;
  TurnStats_T              stats;

  for (i = 0; i < sizeof(peerIp) / sizeof(peerIp[0]); i++)
  {
    sockaddr_initFromString( (struct socket_addr*)&peerIp[i],"192.168.5.22:1234" );
    p_peerIp[i] = &peerIp[i];
  }

  ctx = GotoAllocatedState(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      sizeof(peerIp) / sizeof(peerIp[0]),
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_CreatePermissionOk);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_TRUE(stats.numberOfPeers == 6);


  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_CreatePermissionReqOk_IPv6)
{
  struct socket_addr peerIp;
  struct socket_addr peerIp_2;
  struct socket_addr*        p_peerIp[2];
  int                     ctx;

  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234\0" );
  sockaddr_initFromString( (struct socket_addr*)&peerIp_2,
                           "[2a02:fe0:c410:cb31:e4d:e43f:fecb:bf6b]:1234\0" );
  p_peerIp[0] = (struct socket_addr*)&peerIp;
  p_peerIp[1] = (struct socket_addr*)&peerIp_2;


  ctx = GotoAllocatedState_IPv6(12);
  ASSERT_TRUE( TurnClient_StartCreatePermissionReq(pInst,
                                                   2,
                                                   (const struct socket_addr**)
                                                   p_peerIp) );
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_CreatePermissionOk);
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_CreatePermissionReq_no_IP)
{
  struct socket_addr  peerIp[6];
  struct socket_addr* p_peerIp[6];
  uint32_t                 i;

  for (i = 0; i < sizeof(peerIp) / sizeof(peerIp[0]); i++)
  {
    sockaddr_initFromString( (struct socket_addr*)&peerIp[i],"192.168.5.22:1234" );
    p_peerIp[i] = &peerIp[i];
  }
  p_peerIp[4] = NULL;

  GotoAllocatedState(12);
  ASSERT_FALSE( TurnClient_StartCreatePermissionReq(pInst,
                                                    sizeof(peerIp) /
                                                    sizeof(peerIp[0]),
                                                    (const struct socket_addr**)
                                                    p_peerIp) );
}

CTEST(turnclient, Allocated_CreatePermissionRefresh)
{
  struct socket_addr  peerIp[6];
  struct socket_addr* p_peerIp[6];
  int                      ctx;
  uint32_t                 i;

  for (i = 0; i < sizeof(peerIp) / sizeof(peerIp[0]); i++)
  {
    sockaddr_initFromString( (struct socket_addr*)&peerIp[i],"192.168.5.22:1234" );
    p_peerIp[i] = &peerIp[i];
  }

  ctx = GotoAllocatedState(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      sizeof(peerIp) / sizeof(peerIp[0]),
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_CreatePermissionOk);

  /* verfiy callback is not called again */
  turnResult = TurnResult_Empty;
  Sim_TimerRefreshPermission(ctx);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  ASSERT_TRUE(turnResult == TurnResult_Empty);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_CreatePermissionRefresh_IPv6)
{
  struct socket_addr peerIp;
  struct socket_addr peerIp_2;
  struct socket_addr*        p_peerIp[2];
  int                     ctx;

  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234\0" );
  sockaddr_initFromString( (struct socket_addr*)&peerIp_2,
                           "[2a02:fe0:c410:cb31:e4d:e43f:fecb:bf6b]:1234\0" );
  p_peerIp[0] = (struct socket_addr*)&peerIp;
  p_peerIp[1] = (struct socket_addr*)&peerIp_2;


  ctx = GotoAllocatedState_IPv6(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      2,
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_CreatePermissionOk);

  /* verfiy callback is not called again */
  turnResult = TurnResult_Empty;
  Sim_TimerRefreshPermission(ctx);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  ASSERT_TRUE(turnResult == TurnResult_Empty);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_CreatePermissionErr)
{
  struct socket_addr  peerIp[3];
  struct socket_addr* p_peerIp[3];
  int                      ctx;
  uint32_t                 i;

  for (i = 0; i < sizeof(peerIp) / sizeof(peerIp[0]); i++)
  {
    sockaddr_initFromString( (struct socket_addr*)&peerIp[i],"192.168.5.22:1234" );
    p_peerIp[i] = &peerIp[i];
  }

  ctx = GotoAllocatedState(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      sizeof(peerIp) / sizeof(peerIp[0]),
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx,
                               STUN_MSG_CreatePermissionErrorResponseMsg,
                               4,
                               4);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_PermissionRefreshFail);
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_CreatePermissionErr_IPv6)
{
  struct socket_addr peerIp;
  struct socket_addr peerIp_2;
  struct socket_addr*        p_peerIp[2];
  int                     ctx;

  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234\0" );
  sockaddr_initFromString( (struct socket_addr*)&peerIp_2,
                           "[2a02:fe0:c410:cb31:e4d:e43f:fecb:bf6b]:1234\0" );
  p_peerIp[0] = (struct socket_addr*)&peerIp;
  p_peerIp[1] = (struct socket_addr*)&peerIp_2;

  ctx = GotoAllocatedState_IPv6(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      2,
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx,
                               STUN_MSG_CreatePermissionErrorResponseMsg,
                               4,
                               4);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_PermissionRefreshFail);
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}



CTEST(turnclient, Allocated_CreatePermissionReqAndChannelBind)
{
  struct socket_addr  peerIp[6];
  struct socket_addr* p_peerIp[6];
  int                      ctx;
  uint32_t                 i;

  for (i = 0; i < sizeof(peerIp) / sizeof(peerIp[0]); i++)
  {
    sockaddr_initFromString( (struct socket_addr*)&peerIp[i],"192.168.5.22:1234" );
    p_peerIp[i] = &peerIp[i];
  }

  ctx = GotoAllocatedState(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      sizeof(peerIp) / sizeof(peerIp[0]),
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp[0]);

  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_CreatePermissionOk);

  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_CreatePermissionReqAndChannelBind_IPv6)
{
  struct socket_addr peerIp;
  struct socket_addr peerIp_2;
  struct socket_addr*        p_peerIp[2];
  int                     ctx;

  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234\0" );
  sockaddr_initFromString( (struct socket_addr*)&peerIp_2,
                           "[2a02:fe0:c410:cb31:e4d:e43f:fecb:bf6b]:1234\0" );
  p_peerIp[0] = (struct socket_addr*)&peerIp;
  p_peerIp[1] = (struct socket_addr*)&peerIp_2;



  ctx = GotoAllocatedState_IPv6(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      2,
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);

  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_CreatePermissionResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_CreatePermissionOk);

  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient, Allocated_CreatePermissionErrorAndChannelBind)
{
  struct socket_addr  peerIp[6];
  struct socket_addr* p_peerIp[6];
  int                      ctx;
  uint32_t                 i;

  for (i = 0; i < sizeof(peerIp) / sizeof(peerIp[0]); i++)
  {
    sockaddr_initFromString( (struct socket_addr*)&peerIp[i],"192.168.5.22:1234" );
    p_peerIp[i] = &peerIp[i];
  }

  ctx = GotoAllocatedState(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      sizeof(peerIp) / sizeof(peerIp[0]),
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp[0]);

  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx,
                               STUN_MSG_CreatePermissionErrorResponseMsg,
                               4,
                               4);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_PermissionRefreshFail);

  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, Allocated_CreatePermissionErrorAndChannelBind_IPv6)
{
  struct socket_addr peerIp;
  struct socket_addr peerIp_2;
  struct socket_addr*        p_peerIp[2];
  int                     ctx;

  sockaddr_initFromString( (struct socket_addr*)&peerIp,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234\0" );
  sockaddr_initFromString( (struct socket_addr*)&peerIp_2,
                           "[2a02:fe0:c410:cb31:e4d:e43f:fecb:bf6b]:1234\0" );
  p_peerIp[0] = (struct socket_addr*)&peerIp;
  p_peerIp[1] = (struct socket_addr*)&peerIp_2;


  ctx = GotoAllocatedState_IPv6(12);
  TurnClient_StartCreatePermissionReq(pInst,
                                      2,
                                      (const struct socket_addr**)p_peerIp);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);

  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx,
                               STUN_MSG_CreatePermissionErrorResponseMsg,
                               4,
                               4);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_PermissionRefreshFail);

  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient, GetMessageName)
{
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_BindRequestMsg),
                      "BindRequest") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_BindResponseMsg),
                      "BindResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_BindIndicationMsg),
                      "BindInd") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_BindErrorResponseMsg),
                      "BindErrorResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_AllocateRequestMsg),
                      "AllocateRequest") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(
                        STUN_MSG_AllocateResponseMsg), "AllocateResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_AllocateErrorResponseMsg),
                      "AllocateErrorResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_CreatePermissionRequestMsg),
                      "CreatePermissionReq") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(
                        STUN_MSG_CreatePermissionResponseMsg),
                      "CreatePermissionResp") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(
                        STUN_MSG_CreatePermissionErrorResponseMsg),
                      "CreatePermissionError") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_ChannelBindRequestMsg),
                      "ChannelBindRequest") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_ChannelBindResponseMsg),
                      "ChannelBindResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(
                        STUN_MSG_ChannelBindErrorResponseMsg),
                      "ChannelBindErrorResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_RefreshRequestMsg),
                      "RefreshRequest") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(
                        STUN_MSG_RefreshResponseMsg),   "RefreshResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_RefreshErrorResponseMsg),
                      "RefreshErrorResponse") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(STUN_MSG_DataIndicationMsg),
                      "DataIndication") );
  ASSERT_TRUE( 0 ==
               strcmp(stunlib_getMessageName(
                        STUN_MSG_SendIndicationMsg),   "STUN_MSG_SendInd") );



  ASSERT_TRUE( 0 == strcmp(stunlib_getMessageName(123),   "???") );

}



CTEST(turnclient, SuccessResp)
{
  StunMessage msg;

  msg.msgHdr.msgType = STUN_MSG_BindResponseMsg;
  ASSERT_TRUE( stunlib_isSuccessResponse(&msg) );

}


CTEST(turnclient, ErrorResp)
{
  StunMessage msg;

  msg.msgHdr.msgType = STUN_MSG_BindErrorResponseMsg;
  ASSERT_TRUE( stunlib_isErrorResponse(&msg) );

}


CTEST(turnclient, Resp)
{
  StunMessage msg;

  msg.msgHdr.msgType = STUN_MSG_BindErrorResponseMsg;
  ASSERT_TRUE( stunlib_isResponse(&msg) );

}


CTEST(turnclient, Ind)
{
  StunMessage msg;

  msg.msgHdr.msgType = STUN_MSG_SendIndicationMsg;
  ASSERT_TRUE( stunlib_isIndication(&msg) );

}



CTEST(turnclient, Req)
{
  StunMessage msg;

  msg.msgHdr.msgType = STUN_MSG_BindRequestMsg;
  ASSERT_TRUE( stunlib_isRequest(&msg) );

}



CTEST(turnclient, isTurnChan)
{
  unsigned char req[] =
    "Kinda buffer ready to be overwritten";

  /* We overwrite some of the data, but in this case who cares.. */
  stunlib_encodeTurnChannelNumber(0x4001,
                                  sizeof(req),
                                  (uint8_t*)req);

  ASSERT_TRUE( stunlib_isTurnChannelData(req) );

}


CTEST(turnclient, GetErrorReason)
{
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(3, 0),"Try Alternate") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 0),"Bad Request") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 1),"Unauthorized") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 20),"Unknown Attribute") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 30),"Stale Credentials") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 31),
                           "Integrity Check Failure") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 32),"Missing Username") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 37),"No Binding") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 38),"Stale Nonce") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 41),"Wrong Username") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 42),
                           "Unsupported Transport Protocol") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(5, 00),"Server Error") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(6, 00),"Global Failure") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 86),
                           "Allocation Quota Reached") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(5, 8),
                           "Insufficient Capacity") );
  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(4, 87),"Role Conflict") );

  ASSERT_TRUE( 0 == strcmp(stunlib_getErrorReason(2, 43),"???") );
}

CTEST(turnclient, sendpacket_bound)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[] =
    "123456789abcdef123456789Some data to be sendt. Here and there.\0";

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE( stats.Retransmits == 0);
  ASSERT_TRUE( stats.Failures == 0);
  ASSERT_TRUE( stats.channelBound);

  ASSERT_TRUE( TurnClient_SendPacket(pInst,
                                     buf,
                                     sizeof buf,
                                     sizeof buf - 24,
                                     24,
                                     (struct socket_addr*)&peerIp,
                                     true) );

  ASSERT_TRUE(strcmp( (char*)latestBuf + 4, (char*)buf + 24 ) == 0);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, sendpacket_bound_no_offset)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[300];
  int           offset = 0;
  char          data[] = "Some data to be sendt. Here and there.\0";
  memcpy(buf + offset, data, sizeof data);

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE( stats.Retransmits == 0);
  ASSERT_TRUE( stats.Failures == 0);
  ASSERT_TRUE( stats.channelBound);

  ASSERT_TRUE( TurnClient_SendPacket(pInst,
                                     buf,
                                     sizeof buf,
                                     sizeof data,
                                     offset,
                                     (struct socket_addr*)&peerIp,
                                     true) );

  ASSERT_TRUE(strcmp( (char*)latestBuf + TURN_CHANNEL_DATA_HDR_SIZE,
                      data ) == 0);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient, sendpacket_un_bound)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[300];
  int           offset = 56;
  char          data[] = "Some data to be sendt. Here and there.\0";
  memcpy(buf + offset, data, sizeof data);

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_FALSE(stats.channelBound);

  ASSERT_TRUE( TurnClient_SendPacket(pInst,
                                     buf,
                                     sizeof buf,
                                     sizeof data,
                                     offset,
                                     (struct socket_addr*)&peerIp,
                                     true) );

  ASSERT_TRUE(strcmp( (char*)latestBuf + 36, data ) == 0);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, sendpacket_un_bound_no_offset)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[300];
  int           offset = 0;
  char          data[] = "Some data to be sendt. Here and there.\0";
  memcpy(buf + offset, data, sizeof data);

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_FALSE(stats.channelBound);

  ASSERT_TRUE( TurnClient_SendPacket(pInst,
                                     buf,
                                     sizeof buf,
                                     sizeof data,
                                     offset,
                                     (struct socket_addr*)&peerIp,
                                     true) );

  ASSERT_TRUE(strcmp( (char*)latestBuf + 36, data ) == 0);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, sendpacket_un_bound_small_buffer)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  // 30 在 win下会导致栈溢出
  unsigned char buf[40];
  int           offset = 0;
  char          data[] = "Some data to be sendt. Here and there.\0";
  memcpy(buf + offset, data, sizeof data);

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_FALSE( stats.channelBound);

  ASSERT_FALSE( TurnClient_SendPacket(pInst,
                                      buf,
                                      sizeof buf,
                                      sizeof data,
                                      offset,
                                      (struct socket_addr*)&peerIp,
                                      true) );


  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient,recievepacket_bound)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[] =
    "123456789abcdef123456789Some data to be sendt. Here and there.\0";

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&peerIp);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE( stats.Retransmits == 0);
  ASSERT_TRUE( stats.Failures == 0);
  ASSERT_TRUE( stats.channelBound);

  ASSERT_TRUE( TurnClient_SendPacket(pInst,
                                     buf,
                                     sizeof buf,
                                     sizeof buf - 24,
                                     24,
                                     (struct socket_addr*)&peerIp,
                                     true) );

  ASSERT_TRUE( TurnClient_ReceivePacket(pInst,
                                        latestBuf,
                                        &latestBufLen,
                                        (struct socket_addr*)&peerIp,
                                        sizeof peerIp,
                                        0) );

  ASSERT_TRUE(strcmp( (char*)latestBuf, (char*)buf + 24 ) == 0);

  /* Can we recieve it as well? */



  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient,recievepacket_bound_IPv6)
{
  struct socket_addr addr;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[] =
    "123456789abcdef123456789Some data to be sendt. Here and there.\0";
  sockaddr_initFromString( (struct socket_addr*)&addr,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234\0" );


  ctx = GotoAllocatedState(12);
  TurnClient_StartChannelBindReq(pInst, 0x4001, (struct socket_addr*)&addr);
  TurnClient_HandleTick(pInst);
  Sim_ChanBindOrPermissionResp(ctx, STUN_MSG_ChannelBindResponseMsg, 0, 0);
  TurnClient_HandleTick(pInst);
  ASSERT_TRUE(turnResult == TurnResult_ChanBindOk);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE( stats.Retransmits == 0);
  ASSERT_TRUE( stats.Failures == 0);
  ASSERT_TRUE( stats.channelBound);

  ASSERT_TRUE( TurnClient_SendPacket(pInst,
                                     buf,
                                     sizeof buf,
                                     sizeof buf - 24,
                                     24,
                                     (struct socket_addr*)&addr,
                                     true) );

  ASSERT_TRUE( TurnClient_ReceivePacket(pInst,
                                        latestBuf,
                                        &latestBufLen,
                                        (struct socket_addr*)&addr,
                                        sizeof addr,
                                        0) );

  ASSERT_TRUE(strcmp( (char*)latestBuf, (char*)buf + 24 ) == 0);

  /* Can we recieve it as well? */



  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, recievepacket_un_bound_error)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[300];
  int           offset = 56;
  char          data[] = "Some data to be sendt. Here and there.\0";
  memcpy(buf + offset, data, sizeof data);

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_FALSE(stats.channelBound);

  ASSERT_TRUE( TurnClient_SendPacket(pInst,
                                     buf,
                                     sizeof buf,
                                     sizeof data,
                                     offset,
                                     (struct socket_addr*)&peerIp,
                                     true) );

  ASSERT_FALSE( TurnClient_ReceivePacket(pInst,
                                         latestBuf,
                                         &latestBufLen,
                                         (struct socket_addr*)&peerIp,
                                         sizeof peerIp,
                                         0) );

  ASSERT_TRUE(strcmp( (char*)latestBuf + 36, data ) == 0);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient, recievepacket_un_bound)
{
  struct socket_addr peerIp;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[300];
  int           offset = 56;
  char          data[] = "Some data to be sendt. Here and there.\0";
  size_t        len;
  memcpy(buf + offset, data, sizeof data);

  sockaddr_initFromString( (struct socket_addr*)&peerIp,"192.168.5.22:1234" );

  ctx = GotoAllocatedState(12);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_FALSE(stats.channelBound);

  len = stunlib_EncodeDataIndication(buf,
                                     (unsigned char*)data,
                                     sizeof buf,
                                     sizeof data,
                                     (struct socket_addr*)&peerIp);
  ASSERT_TRUE(len == 76);



  ASSERT_TRUE( TurnClient_ReceivePacket(pInst,
                                        buf,
                                        &len,
                                        (struct socket_addr*)&peerIp,
                                        sizeof peerIp,
                                        0) );

  ASSERT_TRUE(strcmp( (char*)buf, data ) == 0);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, recievepacket_un_bound_IPv6)
{
  struct socket_addr addr;
  int                     ctx;
  TurnStats_T             stats;

  unsigned char buf[300];
  int           offset = 56;
  char          data[] = "Some data to be sendt. Here and there.\0";
  size_t        len;
  memcpy(buf + offset, data, sizeof data);
  sockaddr_initFromString( (struct socket_addr*)&addr,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234\0" );

  ctx = GotoAllocatedState_IPv6(12);

  TurnClientGetStats(pInst,
                     &stats);
  ASSERT_TRUE(stats.Retransmits == 0);
  ASSERT_TRUE(stats.Failures == 0);
  ASSERT_FALSE(stats.channelBound);
  len = stunlib_EncodeDataIndication(buf,
                                     (unsigned char*)data,
                                     sizeof buf,
                                     sizeof data,
                                     (struct socket_addr*)&addr);
  ASSERT_TRUE( len == 88);

  ASSERT_TRUE( TurnClient_ReceivePacket(pInst,
                                        buf,
                                        &len,
                                        (struct socket_addr*)&addr,
                                        sizeof addr,
                                        0) );

  ASSERT_TRUE(strcmp( (char*)buf, data ) == 0);

  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}


CTEST(turnclient, keepalive)
{
  int ctx;
  ctx = GotoAllocatedState(12);
  StunMessage message;
  /* Do we send keepalives? */
  for (int i = 0; i < 500; i++)
  {
    TurnClient_HandleTick(pInst);
  }
  ASSERT_TRUE( stunlib_DecodeMessage(latestBuf,
                                     latestBufLen,
                                     &message,
                                     NULL,
                                     NULL) );
  ASSERT_TRUE( stunlib_isIndication(&message) );
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}

CTEST(turnclient, keepalive_IPv6)
{
  int ctx;
  ctx = GotoAllocatedState_IPv6(12);
  StunMessage message;
  /* Do we send keepalives? */
  for (int i = 0; i < 500; i++)
  {
    TurnClient_HandleTick(pInst);
  }
  ASSERT_TRUE( stunlib_DecodeMessage(latestBuf,
                                     latestBufLen,
                                     &message,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_isIndication(&message) );
  ASSERT_TRUE( sockaddr_alike( (struct socket_addr*)&LastAddress,
                               (struct socket_addr*)&turnServerAddr ) );
  TurnClient_Deallocate(pInst);
  Sim_RefreshResp(ctx);
  ASSERT_TRUE(turnResult == TurnResult_RelayReleaseComplete);
}
