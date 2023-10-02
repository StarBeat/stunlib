/*
 *  See license file
 */

#ifndef STUN_INTERN_H
#define STUN_INTERN_H

#ifdef _WIN32
#include <_time.h>
#else
#include <sys/time.h>
#endif

#include <stunlib.h>
#include "stuntrace.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STUNCLIENT_CTX_UNKNOWN  -1
#define STUN_MAX_ERR_STRLEN    256  /* max size of string in STUN_INFO_FUNC */

/* Internal STUN signals, inputs to stun bind client. */
typedef enum {
  STUN_SIGNAL_BindReq,
  STUN_SIGNAL_BindResp,
  STUN_SIGNAL_BindRespError,
  STUN_SIGNAL_TimerTick,
  STUN_SIGNAL_TimerRetransmit,
  STUN_SIGNAL_ICMPResp,
  STUN_SIGNAL_DeAllocate,
  STUN_SIGNAL_Cancel,

  STUN_SIGNAL_Illegal = -1
} STUN_SIGNAL;


typedef struct
{
  struct socket_addr srcAddr;
  StunMessage             stunRespMessage;
  uint32_t                ICMPtype;
  uint32_t                ttl;
}
StunRespStruct;



/* Internal STUN  states */
typedef enum {
  STUN_STATE_Idle = 0,
  STUN_STATE_WaitBindResp,
  STUN_STATE_Cancelled,
  STUN_STATE_End    /* must be last */
} STUN_STATE;


/* Internal message formats */
typedef struct {
  uint32_t                threadCtx;
  void*                   userCtx;
  struct socket_addr serverAddr;
  struct socket_addr baseAddr;
  bool                    useRelay;
  /* char                    ufrag[300];       / * TBD  =
   *  ICE_MAX_UFRAG_LENGTH* / */
  /* char                    password[300];    / * TBD = ICE_MAX_PASSWD_LENGTH* / */
  /* uint32_t                peerPriority; */
  /* bool                    useCandidate; */
  /* bool                    iceControlling; */
  /* uint64_t                tieBreaker; */
  uint32_t proto;
  uint8_t  ttl;
  /* StunMsgId               transactionId; */
  /* uint32_t                sockhandle; */
  TransactionAttributes transAttr;
  STUN_SENDFUNC         sendFunc;
  STUNCB                stunCbFunc;

  bool addSoftware;
  bool stuntrace;
  bool addTransCnt;
} StunBindReqStruct;

struct StunClientStats
{
  uint32_t InProgress;
  uint32_t BindReqSent;
  uint32_t BindReqSent_ViaRelay;
  uint32_t BindRespReceived;
  uint32_t BindRespReceived_AfterCancel;
  uint32_t BindRespReceived_InIdle;
  uint32_t BindRespReceived_ViaRelay;
  uint32_t BindRespErrReceived;
  uint32_t ICMPReceived;
  uint32_t BindReqReceived;
  uint32_t BindReqReceived_ViaRelay;
  uint32_t BindRespSent;
  uint32_t BindRespSent_ViaRelay;
  uint32_t Retransmits;
  uint32_t Failures;
};

typedef struct
{
  STUN_STATE        state;
  bool              inUse;
  uint32_t          inst;
  StunBindReqStruct stunBindReq;

  STUN_USER_CREDENTIALS userCredentials;
  bool                  authenticated;

  /* returned in allocate resp */
  struct socket_addr rflxAddr;

  /* timers */
  int32_t  TimerRetransmit;
  uint32_t retransmits;

  uint32_t reqTransCnt;
  uint32_t respTransCnt;

  /* RTT Info */
  struct timeval start[STUNCLIENT_MAX_RETRANSMITS];
  struct timeval stop[STUNCLIENT_MAX_RETRANSMITS];



  /* icmp */
  uint32_t ICMPtype;
  /* uint32_t ttl; */

  /* DISCUSS */
  bool hasDiscuss;

  struct StunClientStats stats;
  STUN_CLIENT_DATA*      client;

} STUN_TRANSACTION_DATA;


struct STUN_CLIENT_DATA
{
  void*                 userCtx;
  STUN_TRANSACTION_DATA data [STUN_MAX_TRANSACTIONS];


  /*duplicated for logging on unknown transactions etc.*/
  STUN_INFO_FUNC_PTR     Log_cb;
  void*                  logUserData;
  struct StunClientStats stats;
  struct hiutResult      traceResult;
};


/********************************************/
/******  instance data ********  (internal) */
/********************************************/


/* state function */
typedef void (* STUN_STATE_FUNC)(STUN_TRANSACTION_DATA* pInst,
                                 STUN_SIGNAL            sig,
                                 uint8_t*               payload);

/* entry in state table */
typedef struct
{
  STUN_STATE_FUNC Statefunc;
  const char*     StateStr;
}
STUN_STATE_TABLE;



#ifdef __cplusplus
}
#endif


#endif  /* STUN_INTERN_H */
