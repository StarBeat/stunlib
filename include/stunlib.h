/*
 *  See license file
 */
#ifndef STUNMSG_H
#define STUNMSG_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#include "xnet.h"
#include "macro.h"

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

/*
 * Avoid disrupting std::min() and std::max()
 * when compiling .cpp files that include this
 */
#if !defined(max) && !defined(__cplusplus)
#define max(a, b) ( ( (a) > (b) ) ? (a) : (b) )
#endif
#if !defined(min) && !defined(__cplusplus)
#define min(a, b) ( ( (a) < (b) ) ? (a) : (b) )
#endif

#ifdef STUNLIB_CUSTOM_CONFIG
#include STUNLIB_CUSTOM_CONFIG
#else
#include "stunlib_config.h"
#endif

/*** STUN message classes ***/
#define STUN_CLASS_MASK                            0x0110  /* Bits C0,C1 */
#define STUN_CLASS_REQUEST                         0x0000
#define STUN_CLASS_INDICATION                      0x0010
#define STUN_CLASS_SUCCESS_RESP                    0x0100
#define STUN_CLASS_ERROR_RESP                      0x0110

/*** STUN message methods, including class ***/
#define STUN_MSG_BindRequestMsg                    0x0001
#define STUN_MSG_BindResponseMsg                   0x0101
#define STUN_MSG_BindErrorResponseMsg              0x0111
#define STUN_MSG_BindIndicationMsg                 0x0011

/*** MUSCAT path discovery STUN messages ***/
#define STUN_PathDiscoveryRequestMsg               0x000A
#define STUN_PathDiscoveryResponseMsg              0x010A
#define STUN_PathDiscoveryErrorResponseMsg         0x011A

/*** STUN message methods (TURN extensions), including class ***/
#define STUN_MSG_AllocateRequestMsg                0x0003
#define STUN_MSG_AllocateResponseMsg               0x0103
#define STUN_MSG_AllocateErrorResponseMsg          0x0113

#define STUN_MSG_RefreshRequestMsg                 0x0004
#define STUN_MSG_RefreshResponseMsg                0x0104
#define STUN_MSG_RefreshErrorResponseMsg           0x0114

#define STUN_MSG_CreatePermissionRequestMsg        0x0008
#define STUN_MSG_CreatePermissionResponseMsg       0x0108
#define STUN_MSG_CreatePermissionErrorResponseMsg  0x0118

#define STUN_MSG_ChannelBindRequestMsg             0x0009
#define STUN_MSG_ChannelBindResponseMsg            0x0109
#define STUN_MSG_ChannelBindErrorResponseMsg       0x0119

#define STUN_MSG_SendIndicationMsg                 0x0016
#define STUN_MSG_DataIndicationMsg                 0x0017

/*** STUN attributes ***/
#define STUN_ATTR_MappedAddress      0x0001
#define STUN_ATTR_XorMappedAddress   0x0020  /* =reflexive */
#define STUN_ATTR_Username           0x0006
#define STUN_ATTR_MessageIntegrity   0x0008
#define STUN_ATTR_FingerPrint        0x8028
#define STUN_ATTR_ErrorCode          0x0009
#define STUN_ATTR_Realm              0x0014
#define STUN_ATTR_Nonce              0x0015
#define STUN_ATTR_UnknownAttribute   0x000A
#define STUN_ATTR_Software           0x8022
#define STUN_ATTR_AlternateServer    0x8023
#define STUN_ATTR_TransCount         0x8025

/*Path Discovery test attribute */
#define STUN_ATTR_PD                 0x8041

/*ENF Draft Attributes */
#define STUN_ATTR_EnfFlowDescription  0xC001
#define STUN_ATTR_EnfNetworkStatus    0xC002

/*STUNTrace Attributes (Experimental) */
#define STUN_ATTR_TTL                0x8055

/* STUN attributes (TURN extensions) */
#define STUN_ATTR_ChannelNumber       0x000c
#define STUN_ATTR_Lifetime            0x000d
#define STUN_ATTR_XorPeerAddress      0x0012
#define STUN_ATTR_Data                0x0013
#define STUN_ATTR_XorRelayAddress     0x0016   /* relay address */
#define STUN_ATTR_RequestedAddrFamily 0x0017   /* RFC 6156 */
#define STUN_ATTR_EvenPort            0x0018
#define STUN_ATTR_RequestedTransport  0x0019
#define STUN_ATTR_DontFragment        0x001a
#define STUN_ATTR_ReservationToken    0x0022

/* STUN attributes (ICE extensions) */
#define STUN_ATTR_Priority           0x0024
#define STUN_ATTR_UseCandidate       0x0025
#define STUN_ATTR_ICEControlled      0x8029
#define STUN_ATTR_ICEControlling     0x802A


/** IP Addr family **/
#define STUN_ADDR_IPv4Family         0x01
#define STUN_ADDR_IPv6Family         0x02


/*** STUN Error attribute codes ***/

/* STUN RFC5389 */
#define STUN_ERROR_TRY_ALTERNATE             300
#define STUN_ERROR_BAD_REQUEST               400
#define STUN_ERROR_UNAUTHORIZED              401
#define STUN_ERROR_UNKNOWN_ATTR              420
#define STUN_ERROR_STALE_NONCE               438

#define STUN_ERROR_SERVER_ERROR              500

/* TURN extensions */
#define STUN_ERROR_NO_BINDING                437
#define STUN_ERROR_ADDR_FAMILY_NOT_SUPPORTED 440
#define STUN_ERROR_WRONG_USERNAME            441
#define STUN_ERROR_UNSUPPORTED_PROTO         442
#define STUN_ERROR_PEER_ADDR_MISMATCH        443
#define STUN_ERROR_QUOTA_REACHED             486
#define STUN_ERROR_INSUFFICIENT_CAPACITY     508

/* ICE extensions */
#define STUN_ERROR_ROLE_CONFLICT             487

/* (old) STUN RFC3489 */
#define STUN_ERROR_STALE_CREDS               430
#define STUN_ERROR_INTEG_CHECK_FAIL          431
#define STUN_ERROR_MISSING_USERNAME          432
#define STUN_ERROR_GLOBAL_FAIL               600




typedef enum
{
  StunKeepAliveUsage_Outbound,
  StunKeepAliveUsage_Ice
}
StunKeepAliveUsage;

typedef struct {
  uint8_t octet[STUN_MAGIC_COOKIE_SIZE];
} StunMsgCookie;

typedef struct
{
  uint8_t octet[STUN_MSG_ID_SIZE];
} StunMsgId;

/* Stun message header.
 */
typedef struct
{
  uint16_t      msgType;
  uint16_t      msgLength;
  StunMsgId     id;
  StunMsgCookie cookie;
} StunMsgHdr;


typedef struct
{
  uint16_t type;
  uint16_t length;
} StunAtrHdr;


typedef struct
{
  uint16_t port;
  uint32_t addr;
} StunAddress4;

typedef struct
{
  uint16_t port;
  uint8_t  addr[16];
} StunAddress6;

typedef struct
{
  uint8_t familyType;     /* IP 4 or 6, se above for define */
  union
  {
    StunAddress4 v4;
    StunAddress6 v6;
  } addr;
} StunIPAddress;

typedef struct
{
  uint16_t reserved;
  uint8_t  errorClass;
  uint8_t  number;
  char     reason[STUN_MAX_STRING];
  char     padChar;
  uint16_t sizeReason;
} StunAtrError;

typedef struct
{
  uint16_t attrType[STUN_MAX_UNKNOWN_ATTRIBUTES];
  uint16_t numAttributes;
} StunAtrUnknown;

typedef struct
{
  char     value[STUN_MAX_ATTR_SIZE];
  char     padChar;
  uint16_t sizeValue;
} StunAtrString;

typedef struct
{
  uint16_t      offset;
  unsigned char hash[20];
} StunAtrIntegrity;


typedef struct
{
  uint32_t value;
} StunAtrValue;

typedef struct
{
  uint64_t value;
} StunAtrDoubleValue;


typedef struct
{
  uint32_t dataLen;
  uint32_t offset;
  uint8_t* pData;
} StunData;

typedef struct
{
  uint16_t channelNumber;
  uint16_t rffu;            /* reserved */
}
StunAtrChannelNumber;

typedef struct
{
  uint8_t protocol;
  uint8_t rffu[3];          /* reserved */
}
StunAtrRequestedTransport;


typedef struct
{
  /*first 4 bytes for type,
   *  rest is for padding (future use)*/
  uint8_t family;
  uint8_t rffu[3];          /* reserved */
}StunAttrRequestedAddrFamily;


typedef struct
{
  uint8_t evenPort;
  uint8_t pad[3];
}
StunAtrEvenPort;


typedef struct
{
  /*4 bits*/
  uint8_t type;
  /*4 bits*/
  uint8_t  tbd;
  uint16_t bandwidthMax;
  uint8_t  pad;
}
StunAtrEnfFlowDescription;

typedef struct
{
  uint8_t  flags;
  uint8_t  nodeCnt;
  uint16_t tbd;
  uint16_t upMaxBandwidth;
  uint16_t downMaxBandwidth;
}
StunAtrEnfNetworkStatus;

typedef struct
{
  uint16_t reserved;
  uint8_t  reqCnt;
  uint8_t  respCnt;
}
StunAtrTransCount;

typedef struct
{
  uint16_t average;
  uint16_t max;
}
StunAtrBandwidthUsage;

typedef struct
{
  uint8_t  ttl;
  uint8_t  pad_8;
  uint16_t pad_16;
}
StunAtrTTL;

typedef struct
{
  char          stunUserName[STUN_MSG_MAX_USERNAME_LENGTH];
  char          stunPassword[STUN_MSG_MAX_PASSWORD_LENGTH];
  char          realm[STUN_MSG_MAX_REALM_LENGTH];
  char          nonce[STUN_MSG_MAX_NONCE_LENGTH];
  unsigned char key[20];     /* for long  term cred: key= md5 hash of
                              * username:realm:pass  */
                             /* for short term cred: key=password  */
} STUN_USER_CREDENTIALS;



typedef struct
{
  /* Core Values*/
  StunMsgId transactionId;
  uint32_t  sockhandle;
  /* ICE Related */
  char     username[STUN_MSG_MAX_USERNAME_LENGTH];
  char     password[STUN_MSG_MAX_PASSWORD_LENGTH];
  uint32_t peerPriority;
  bool     useCandidate;
  bool     iceControlling;
  uint64_t tieBreaker;
  /* ENF */
  bool                      addEnf;
  StunAtrEnfFlowDescription enfFlowDescription;
  StunAtrEnfNetworkStatus   enfNetworkStatus;
  StunAtrEnfNetworkStatus   enfNetworkStatusResp;

  /* MISC */

} TransactionAttributes;


/* Decoded  STUN message */
typedef struct
{
  StunMsgHdr msgHdr;

  bool          hasMappedAddress;
  StunIPAddress mappedAddress;

  bool          hasUsername;
  StunAtrString username;

  bool          hasIntegirtyKey;
  StunAtrString integrityKey;

  bool             hasMessageIntegrity;
  StunAtrIntegrity messageIntegrity;

  bool hasFingerPrint;   /* attribute never stored */

  bool         hasErrorCode;
  StunAtrError errorCode;

  bool           hasUnknownAttributes;
  StunAtrUnknown unknownAttributes;

  bool          hasXorMappedAddress;
  StunIPAddress xorMappedAddress;

  bool          hasSoftware;
  StunAtrString software;

  bool          hasPathDiscovery;
  StunAtrString path_discovery;

  bool         hasLifetime;
  StunAtrValue lifetime;

  bool          hasAlternateServer;
  StunIPAddress alternateServer;

  uint32_t      xorPeerAddrEntries;
  StunIPAddress xorPeerAddress[STUN_MAX_PEER_ADDR];

  bool     hasData;
  StunData data;

  bool          hasNonce;
  StunAtrString nonce;

  bool          hasRealm;
  StunAtrString realm;

  StunIPAddress xorRelayAddressTMP;

  bool          hasXorRelayAddressIPv4;
  StunIPAddress xorRelayAddressIPv4;

  bool          hasXorRelayAddressIPv6;
  StunIPAddress xorRelayAddressIPv6;

  bool hasXorRelayAddressSSODA;

  /* Used when parsing message */
  StunAttrRequestedAddrFamily requestedAddrFamilyTMP;

  bool                        hasRequestedAddrFamilyIPv4;
  StunAttrRequestedAddrFamily requestedAddrFamilyIPv4;

  bool                        hasRequestedAddrFamilyIPv6;
  StunAttrRequestedAddrFamily requestedAddrFamilyIPv6;

  bool hasRequestedAddrFamilySSODA;

  bool                 hasChannelNumber;
  StunAtrChannelNumber channelNumber;

  bool         hasPriority;
  StunAtrValue priority;

  bool               hasControlling;
  StunAtrDoubleValue controlling;

  bool               hasControlled;
  StunAtrDoubleValue controlled;

  bool                      hasRequestedTransport;
  StunAtrRequestedTransport requestedTransport;

  bool            hasEvenPort;
  StunAtrEvenPort evenPort;

  bool               hasReservationToken;
  StunAtrDoubleValue reservationToken;

  bool                      hasEnfFlowDescription;
  StunAtrEnfFlowDescription enfFlowDescription;

  bool       hasTTL;
  StunAtrTTL ttl;

  /*After Integrity attr*/
  bool                    hasEnfNetworkStatus;
  StunAtrEnfNetworkStatus enfNetworkStatus;

  /*Integrity protected*/
  bool                    hasEnfNetworkStatusResp;
  StunAtrEnfNetworkStatus enfNetworkStatusResp;

  bool              hasTransCount;
  StunAtrTransCount transCount;

  /* No value, only flaged */
  bool hasUseCandidate;
  bool hasDontFragment;
} StunMessage;

/* Defines how a user of stun sends data on e.g. socket */
/* context - e.g. socket handle */
/* ptr to buffer to send */
/* length of send buffer */
/* Optional if connected to socket */
/* User context data. Optional */
/* TTL to set on IP packet, 0 is ignored */

typedef void (* STUN_SENDFUNC)(void*                  ctx,
                               int                    sockHandle,
                               const uint8_t*         buffer,
                               int                    bufLen,
                               const struct socket_addr* dstAddr,
                               int                    proto,
                               bool                   useRelay,
                               const uint8_t          ttl);

/* Defines how errors are reported */
typedef void (* STUN_ERR_FUNC)(const char* fmt,
                               va_list     ap);


/**********************
***** API Funcs ******
**********************/

/* transaction id compare */
FUNC_DECL bool stunlib_transIdIsEqual(const StunMsgId* a,
                       const StunMsgId* b);

/***********************************************/
/*************  Decode functions ***************/
/***********************************************/

/*!
 * STUNLIB_isStunMsg() - use this function to demux STUN messages from a media
 * stream such as RTP or RTCP
 * \param payload        payload  to check (e.g. as received in RTP stream)
 * \param length         payload length
 * \return               TRUE if message is a STUN message
 */
FUNC_DECL bool stunlib_isStunMsg(const uint8_t* payload,
                  uint16_t       length);

/*!
 * stunlib_isTurnChannelData - use this function to demux STUN messages from a
 * media stream such as RTP or RTCP
 * \param payload        payload  to check (e.g. as received in RTP stream)
 * \return               TRUE if message is TURN Channel Data
 */
FUNC_DECL bool stunlib_isTurnChannelData(const uint8_t* payload);


/*!
 * stunDecodeMessage() -  Decode and parse a STUN serialised message
 *
 * \param buf             serialised buffer, network order
 * \param buflen          Length of buffer
 * \param message         Store parsed mesage here
 * \param stream          debug stream (NULL=no debug)
 * \return                True if parsing OK.
 */
FUNC_DECL bool stunlib_DecodeMessage(const uint8_t*  buf,
                      size_t          bufLen,
                      StunMessage*    message,
                      StunAtrUnknown* unknowns,
                      FILE*           stream);

/*!
 * stunlib_checkIntegrity -  Checks the integrity attribute. Be sure to send in
 * the
 *                            correct key. simple Simple password for short
 * term.
 *                            MD5(user:realm:pass) for long term.
 * \param buf             serialised buffer, network order
 * \param buflen          Length of buffer
 * \param message         STUN/TURN message to check integrity on.
 * \param integrityKey    Integrity key, password used to calculate integrity.
 */

FUNC_DECL bool stunlib_checkIntegrity(const uint8_t* buf,
                       size_t         bufLen,
                       StunMessage*   message,
                       uint8_t*       integrityKey,
                       int            integrityKeyLen);

/*!
 * STUNLIB_isRequest() - Test if  decoded stun message is a request
 * \param msg            STUN message to check
 * \return               TRUE if message is a request
 */
FUNC_DECL bool stunlib_isRequest(const StunMessage* msg);

/*!
 * STUNLIB_isSuccessResponse() - Test if decoded stun message is a STUN success
 * response
 * \param msg            decoded STUN message to check
 * \return               TRUE if message is a success response
 */
FUNC_DECL bool stunlib_isSuccessResponse(const StunMessage* msg);

/*!
 * STUNLIB_isErrorResponse() - Test if decoded stun message is a STUN error
 * response
 * \param msg            decoded STUN message to check
 * \return               TRUE if message is an error response
 */
FUNC_DECL bool stunlib_isErrorResponse(const StunMessage* msg);


/*!
 * STUNLIB_isResponse() - Test if decoded stun message is a STUN (success or
 * error) response
 * \param msg            decoded STUN message to check
 * \return               TRUE if message is a response
 */
FUNC_DECL bool stunlib_isResponse(const StunMessage* msg);

/*!
 * STUNLIB_isIndication() - Test if decoded stun message is a STUN indication
 * \param msg            STUN message to check
 * \return               TRUE if message is an indication
 */
FUNC_DECL bool stunlib_isIndication(const StunMessage* msg);


FUNC_DECL uint16_t stunlib_StunMsgLen (const uint8_t* payload);

FUNC_DECL unsigned int stunlib_decodeTurnChannelNumber(uint16_t*      channelNumber,
                                uint16_t*      length,
                                const uint8_t* buf);


/***********************************************/
/*************  Encode functions ***************/
/***********************************************/


/*!
 * stunEncodeMessage() - Encode/serialise a STUN message into buffer from
 * StunMessage struct
 * \param message        STUN message to encode
 * \param buf            Buffer to store encoded STUN message in
 * \param bufLen         Length of encoded buffer
 * \param key            Used to calculate message integrity attribute, key in
 * HMAC-SHA1 alg.
 *                       For Long term credentials = 128 bit MD5 hash of
 * username+nonce+password. (created using STUNMSG_createMD5Key())
 *                       For short term credantials = password
 * \param keyLen         length of key
 * \param verbose        Verbose
 * \return               0 if msg encode fails, else the length of the encoded
 * message (including any padding)
 */
FUNC_DECL uint32_t stunlib_encodeMessage(StunMessage*   message,
                      unsigned char* buf,
                      unsigned int   bufLen,
                      unsigned char* key,
                      unsigned int   keyLen,
                      FILE*          stream);


/* encode a stun keepalive, return the length or 0 if it fails
 * \param usage     - Ice results in  BindingIndication, Outbound results in
 * BindingRequest
 * \param transId   - ptr to transaction id
 * \param buf       - Buffer to store encoded STUN message in
 * \param bufLen    - Length of encoded buffer
 */
FUNC_DECL uint32_t stunlib_encodeStunKeepAliveReq(StunKeepAliveUsage usage,
                               StunMsgId*         transId,
                               uint8_t*           buf,
                               int                bufLen);


/* encode a stun Outbound Keepalive response, return the length or 0 if it fails
 * \param transId   - ptr to transaction id
 * \param srvrRflxAddr - ptr to server reflexive address
 * \param buf       - Buffer to store encoded STUN message in
 * \param bufLen    - Length of encoded buffer
 */
FUNC_DECL uint32_t stunlib_encodeStunKeepAliveResp(StunMsgId*     transId,
                                StunIPAddress* srvrRflxAddr,
                                uint8_t*       buf,
                                int            bufLen);


/*
 *  stunlib_encodeTurnChannelNumber() - Encode/serialise channel numbetr and
 * length fields of Turn Channel Data
 *  \param channelNumber    TURN Channel Number
 *  \param length           Length of application data. (=no. of bytes following
 * ChannelNumber/Length).
 *  \param buf              Destination
 */
FUNC_DECL unsigned int stunlib_encodeTurnChannelNumber(uint16_t       channelNumber,
                                uint16_t       length,
                                unsigned char* buf);

/*
 * encode stun sendIndication
 * \param stunbuf       Destination, encoded stun message
 * \param dataBuf       payload. Note use NULL if payload is already inplace in
 * stunBuf (zero copy)
 * \param maxBufSize    Size of destination buffer
 * \param payloadLength Len of data
 * \param dstAddr       Destination
 */
FUNC_DECL uint32_t stunlib_EncodeSendIndication(uint8_t*               stunBuf,
                             uint8_t*               dataBuf,
                             uint32_t               maxBufSize,
                             uint32_t               payloadLength,
                             const struct socket_addr* dstAddr);

/*
 * encode stun DataIndication (note: only used by a server or for simulating
 * server)
 * \param stunbuf       Destination, encoded stun message
 * \param dataBuf       payload. Note use NULL if payload is already inplace in
 * stunBuf (zero copy)
 * \param maxBufSize    Size of destination buffer
 * \param payloadLength Len of data
 * \param dstAddr       Destination
 */
FUNC_DECL uint32_t stunlib_EncodeDataIndication(uint8_t*               stunBuf,
                             uint8_t*               dataBuf,
                             uint32_t               maxBufSize,
                             uint32_t               payloadLength,
                             const struct socket_addr* dstAddr);


/***********************************************/
/***********      utilities       **************/
/***********************************************/

FUNC_DECL void stun_printMessage(FILE*              stream,
                  const StunMessage* pMsg);
FUNC_DECL void stun_printTransId(FILE*            stream,
                  const StunMsgId* pId);

/* \return random turn channel number in range STUN_MIN_CHANNEL_ID..
 * STUN_MAX_CHANNEL_ID */
FUNC_DECL uint16_t stunlib_createRandomTurnChanNum(void);

/*
 * Convert decoded msgType to string
 */
FUNC_DECL char const* stunlib_getMessageName(uint16_t msgType);

/*!
 * stunGetErrorReason() - Given an errorClass and number, returns standard
 * reason text
 * \param errorClass
 * \param errorNumber
 */
FUNC_DECL char const* stunlib_getErrorReason(uint16_t errorClass,
                       uint16_t errorNumber);


FUNC_DECL void stunlib_setIP4Address(StunIPAddress* pIpAdr,
                      uint32_t       addr,
                      uint16_t       port);
/* Addr is 4 long. With most significant DWORD in pos 0 */
FUNC_DECL void stunlib_setIP6Address(StunIPAddress* pIpAdr,
                      const uint8_t  addr[16],
                      const uint16_t port);
FUNC_DECL int stunlib_compareIPAddresses(const StunIPAddress* pS1,
                           const StunIPAddress* pS2);
FUNC_DECL void stunlib_printBuffer(FILE*          stream,
                    const uint8_t* pBuf,
                    int            len,
                    char const*    szHead);


FUNC_DECL void stunlib_createId(StunMsgId* pId);

FUNC_DECL bool stunlib_addRealm(StunMessage* stunMsg,
                 const char*  realm,
                 char         padChar);
FUNC_DECL bool stunlib_addRequestedTransport(StunMessage* stunMsg,
                              uint8_t      protocol);
FUNC_DECL bool stunlib_addRequestedAddrFamily(StunMessage* stunMsg,
                               int          sa_family);
FUNC_DECL bool stunlib_addUserName(StunMessage* stunMsg,
                    const char*  userName,
                    char         padChar);
FUNC_DECL bool stunlib_addNonce(StunMessage* stunMsg,
                 const char*  nonce,
                 char         padChar);
FUNC_DECL bool stunlib_addSoftware(StunMessage* stunMsg,
                    const char*  software,
                    char         padChar);
FUNC_DECL bool stunlib_addError(StunMessage* stunMsg,
                 const char*  reasonStr,
                 uint16_t     classAndNumber,
                 char         padChar);
FUNC_DECL bool stunlib_addChannelNumber(StunMessage* stunMsg,
                         uint16_t     channelNumber);
FUNC_DECL uint32_t stunlib_calculateFingerprint(const uint8_t* buf,
                             size_t         len);
FUNC_DECL bool stunlib_checkFingerPrint(const uint8_t* buf,
                         uint32_t       fpOffset);


/* Concat  username+realm+passwd into string "<username>:<realm>:<password>"
 * then run the MD5 alg.
 * on this string to create a 128but MD5 hash in md5key.
 *
 * \param   md5Key    calculated md5key, must be min 16 bytes.
 * \param   userName  C string
 * \param   realm     C string
 * \param   password  C string
 */
FUNC_DECL void stunlib_createMD5Key(unsigned char* md5key,
                     const char*    userName,
                     const char*    realm,
                     const char*    password);

#ifdef __cplusplus
}
#endif

#endif /* STUNMSG_H*/
