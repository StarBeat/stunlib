

#ifndef STUNSERVER_H
#define STUNSERVER_H


#include "stunlib.h"   /* stun enc/dec and msg formats*/
#include <stdint.h>
#include "xnet.h"
#include "stunclient.h"
#include "stun_intern.h"
#include "macro.h"
#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

FUNC_DECL bool CreateConnectivityBindingResp(StunMessage*           stunMsg,
                                StunMsgId              transactionId,
                                const struct socket_addr* mappedSockAddr,
                                uint8_t                reqTrnspCnt,
                                uint8_t                respTrnspCnt,
                                uint8_t                enf_flags,
                                uint8_t                enf_nodeCnt,
                                uint16_t               enf_upMaxBandwidth,
                                uint16_t               enf_downMaxBandwidth,
                                uint16_t               response,
                                uint32_t               responseCode);


/********* Server handling: send STUN BIND RESP *************/
FUNC_DECL bool StunServer_SendConnectivityBindingResp(STUN_CLIENT_DATA *      clientData,
                                           int32_t globalSocketId,
                                           StunMsgId transactionId,
                                           const char*            password,
                                           const struct socket_addr* mappedAddr,
                                           const struct socket_addr* dstAddr,
                                           uint8_t reqTrnspCnt,
                                           uint8_t respTrnspCnt,
                                           uint8_t                enf_flags,
                                           uint8_t                enf_nodeCnt,
                                           uint16_t               enf_upMaxBandwidth,
                                           uint16_t               enf_downMaxBandwidth,
                                           void*                  userData,
                                           STUN_SENDFUNC sendFunc,
                                           int proto,
                                           bool useRelay,
                                           uint32_t responseCode);

/********** Server handling:  incoming STUN BIND REQ **********/
FUNC_DECL bool StunServer_HandleStunIncomingBindReqMsg(STUN_CLIENT_DATA *       clientData,
                                            STUN_INCOMING_REQ_DATA * pReq,
                                            const StunMessage *      stunMsg,
                                            bool fromRelay);
#endif
