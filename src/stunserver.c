
#include <stdint.h>
#include <string.h>

#include "stunserver.h"



bool
CreateConnectivityBindingResp(StunMessage*           stunMsg,
                              StunMsgId              transactionId,
                              const struct socket_addr* mappedSockAddr,
                              uint8_t                reqTrnspCnt,
                              uint8_t                respTrnspCnt,
                              uint8_t                enf_flags,
                              uint8_t                enf_nodeCnt,
                              uint16_t               enf_upMaxBandwidth,
                              uint16_t               enf_downMaxBandwidth,
                              uint16_t               response,
                              uint32_t               responseCode)
{
  StunIPAddress mappedAddr;

  if ( !sockaddr_isSet(mappedSockAddr) )
  {
    return false;
  }

  memset(stunMsg, 0, sizeof *stunMsg);
  stunMsg->msgHdr.msgType = response;

  if (reqTrnspCnt != 0)
  {
    stunMsg->hasTransCount      = true;
    stunMsg->transCount.respCnt = respTrnspCnt;
    stunMsg->transCount.reqCnt  = reqTrnspCnt;
  }

  if (mappedSockAddr->isv4)
  {
    mappedAddr.familyType   =  STUN_ADDR_IPv4Family;
    mappedAddr.addr.v4.port = sockaddr_port_ntohs(mappedSockAddr);
    mappedAddr.addr.v4.addr = sockaddr_addr_ntohl(mappedSockAddr);

  }
  else
  {
    mappedAddr.familyType   =  STUN_ADDR_IPv6Family;
    mappedAddr.addr.v6.port = sockaddr_port_ntohs(mappedSockAddr);

    /*TODO: will this be correct ? */
    memcpy( mappedAddr.addr.v6.addr, sockaddr_get_raw(mappedSockAddr),
            sizeof(mappedAddr.addr.v6.addr) );
  }

  /*id*/
  stunMsg->msgHdr.id = transactionId;

  /* The XOR address MUST be added according to the RFC */
  stunMsg->hasXorMappedAddress = true;
  stunMsg->xorMappedAddress    = mappedAddr;


  /* ENF */
  if (enf_nodeCnt > 0)
  {
    stunMsg->hasEnfNetworkStatus = true;
    memset( &stunMsg->enfNetworkStatus, 0,sizeof(StunAtrEnfNetworkStatus) );
    stunMsg->hasEnfNetworkStatusResp = true;
    stunMsg->enfNetworkStatusResp.flags            = enf_flags;
    stunMsg->enfNetworkStatusResp.nodeCnt          = enf_nodeCnt;
    stunMsg->enfNetworkStatusResp.tbd              = 0;
    stunMsg->enfNetworkStatusResp.upMaxBandwidth   = enf_upMaxBandwidth;
    stunMsg->enfNetworkStatusResp.downMaxBandwidth = enf_downMaxBandwidth;
  }

  if (responseCode != 200)
  {
    stunMsg->hasErrorCode         = true;
    stunMsg->errorCode.errorClass = responseCode / 100;
    stunMsg->errorCode.number     = (uint8_t) (responseCode % 100);
    if (responseCode == 487)
    {
      strncpy( stunMsg->errorCode.reason, "Role Conflict",
               sizeof (stunMsg->errorCode.reason) );
      stunMsg->errorCode.sizeReason = strlen(stunMsg->errorCode.reason);
    }
    else if (responseCode == 400)
    {
      strncpy( stunMsg->errorCode.reason, "Bad Request",
               sizeof (stunMsg->errorCode.reason) );
      stunMsg->errorCode.sizeReason = strlen(stunMsg->errorCode.reason);
    }
  }

  return true;
}


static bool
SendConnectivityBindResponse(STUN_CLIENT_DATA*      clientData,
                             int32_t                globalSocketId,
                             StunMessage*           stunRespMsg,
                             const char*            password,
                             const struct socket_addr* dstAddr,
                             void*                  userData,
                             STUN_SENDFUNC          sendFunc,
                             int                    proto,
                             bool                   useRelay)
{
  uint8_t stunBuff[STUN_MAX_PACKET_SIZE];
  int     stunLen;

  (void) userData;
  /* encode bind Response */
  stunLen = stunlib_encodeMessage(stunRespMsg,
                                  (uint8_t*)stunBuff,
                                  STUN_MAX_PACKET_SIZE,
                                  (unsigned char*)password,           /* md5key
                                                                      **/
                                  password ? strlen(password) : 0,    /* keyLen
                                                                      **/
                                  NULL);
  if (!stunLen)
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT>  Failed to encode Binding request response\n");
    return false;
  }

  /* send */
  /* sendFunc(globalSocketId, stunBuff, stunLen, dstAddr, useRelay, 0); */
  sendFunc(clientData->userCtx,
           globalSocketId,
           stunBuff,
           stunLen,
           dstAddr,
           proto,
           useRelay,
           0);
  clientData->stats.BindRespSent++;
  return true;
}


/********* Server handling of STUN BIND RESP *************/
bool
StunServer_SendConnectivityBindingResp(STUN_CLIENT_DATA*      clientData,
                                       int32_t                globalSocketId,
                                       StunMsgId              transactionId,
                                       const char*            password,
                                       const struct socket_addr* mappedAddr,
                                       const struct socket_addr* dstAddr,
                                       uint8_t                reqTrnspCnt,
                                       uint8_t                respTrnspCnt,
                                       uint8_t                enf_flags,
                                       uint8_t                enf_nodeCnt,
                                       uint16_t               enf_upMaxBandwidth,
                                       uint16_t               enf_downMaxBandwidth,
                                       void*                  userData,
                                       STUN_SENDFUNC          sendFunc,
                                       int                    proto,
                                       bool                   useRelay,
                                       uint32_t               responseCode)
{
  StunMessage stunRespMsg;

  /* format */
  if ( CreateConnectivityBindingResp(&stunRespMsg,
                                     transactionId,
                                     mappedAddr,
                                     reqTrnspCnt,
                                     respTrnspCnt,
                                     enf_flags,
                                     enf_nodeCnt,
                                     enf_upMaxBandwidth,
                                     enf_downMaxBandwidth,
                                     (responseCode ==
                                      200) ? STUN_MSG_BindResponseMsg :
                                     STUN_MSG_BindErrorResponseMsg,
                                     responseCode) )
  {
    /* encode and send */
    if ( SendConnectivityBindResponse(clientData,
                                      globalSocketId,
                                      &stunRespMsg,
                                      password,
                                      dstAddr,
                                      userData,
                                      sendFunc,
                                      proto,
                                      useRelay) )
    {
      return true;
    }
  }
  return false;
}


/********** Server handling of incoming STUN BIND REQ **********/
bool
StunServer_HandleStunIncomingBindReqMsg(STUN_CLIENT_DATA*       clientData,
                                        STUN_INCOMING_REQ_DATA* pReq,
                                        const StunMessage*      stunMsg,
                                        bool                    fromRelay)
{
  if (!clientData)
  {
    return false;
  }

  memcpy( &pReq->transactionId, &stunMsg->msgHdr.id, sizeof(StunMsgId) );

  pReq->fromRelay = fromRelay;

  if (stunMsg->hasUsername)
  {
    strncpy( pReq->ufrag, stunMsg->username.value,
             min(stunMsg->username.sizeValue, STUN_MAX_STRING) );
    if (stunMsg->username.sizeValue < STUN_MAX_STRING)
    {
      pReq->ufrag[stunMsg->username.sizeValue] = '\0';
    }
    else
    {
      pReq->ufrag[STUN_MAX_STRING - 1] = '\0';
    }
  }
  else
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT> Missing Username in Binding Request\n");
    return false;
  }

  if (stunMsg->hasPriority)
  {
    pReq->peerPriority = stunMsg->priority.value;
  }
  else
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT> Missing Priority in Binding Request\n");
    return false;
  }

  pReq->useCandidate = stunMsg->hasUseCandidate;

  if (stunMsg->hasControlling)
  {
    pReq->iceControlling = true;
    pReq->tieBreaker     = stunMsg->controlling.value;
  }
  else
  {
    pReq->iceControlling = false;
  }

  if (stunMsg->hasControlled)
  {
    pReq->iceControlled = true;
    pReq->tieBreaker    = stunMsg->controlled.value;
  }
  else
  {
    pReq->iceControlled = false;
  }

  if (fromRelay)
  {
    clientData->stats.BindReqReceived_ViaRelay++;
  }
  clientData->stats.BindReqReceived++;

  return true;
}
