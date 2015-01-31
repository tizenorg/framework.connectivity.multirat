#ifndef MULTIRAT_SB_HTTP_H_
#define MULTIRAT_SB_HTTP_H_

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/netdevice.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <poll.h>

#define MAX_HISTORY 20

#define CONNECTION_REQ_HEADER            "Connection:"
#define ACCEPT_RANGE_REQ_HEADER          "Accept-Ranges:"
#define CONTLEN_REQ_HEADER               "Content-Length:"
#define RANGELEN_REQ_HEADER_CMP1              "Range: bytes"
#define RANGELEN_REQ_HEADER_CMP2              "Range:bytes"
#define RANGELEN_REQ_HEADER              "Range: bytes"
#define CONTYPE_REQ_HEADER               "Content-Type:"
#define IF_RANGE                         "If-Range:"

#define LEN_CONNECTION_REQ_HEADER        11
#define LEN_ACCEPT_RANGE_REQ_HEADER      14
#define LEN_CONTLEN_REQ_HEADER           15
#define LEN_RANGELEN_REQ_HEADER_CMP1     12
#define LEN_RANGELEN_REQ_HEADER_CMP2     11
//#define LEN_RANGELEN_REQ_HEADER          7
#define LEN_RANGELEN_REQ_HEADER          6
#define LEN_CONTYPE_REQ_HEADER           13
#define LEN_IF_RANGE                     9

#define CONNECTION_RSP_HEADER		"Connection:"
#define CONTLEN_RSP_HEADER		"Content-Length:"
#define ACCEPT_RANGE_RSP_HEADER		"Accept-Ranges:"
#define CONTRANGE_RSP_HEADER		"Content-Range:"
#define LOCATION_RSP_HEADER		"Location:"

#define LEN_CONNECTION_RSP_HEADER        11
#define LEN_CONTLEN_RSP_HEADER           15
#define LEN_ACCEPT_RANGE_RSP_HEADER      14
#define LEN_CONTRANGE_RSP_HEADER         14
#define LEN_LOCATION_RSP_HEADER		9

#define END_OF_HEADERS                   "\r\n\r\n"
#define END_OF_LINE                      "\r\n"
#define LEN_OF_CRLF                      2

#define HTTP_RSP_SOCKET_ERROR            -2
#define HTTP_RSP_DECODING_ERROR          -1
#define HTTP_RSP_DECODING_SUCCESS        0
#define HTTP_RSP_REDIRECT					  1
#define TIME_OUT_MILLISEC                30000
#define TMAX                             20
#define INET_ADDRSTRLENG                 50
#define MAX_CONT_LEN                     50
#define MICROSECS_IN_SEC                  1000000

#define MAX_INTERFACES                   2

#define STATE_THREAD_RUNNING             1
#define STATE_THREAD_STOPPED             2

#define THREAD_WAIT                      0
#define THREAD_EXIT                      1
#define THREAD_CONTINUE                  2

#define SOCKET_CREATION_FAILED           -1
#define SOCKET_BIND_FAILED               -2

#define MAX_TEMP_BUFF                    4000
#define MAX_HEADER_SIZE                  (16 * 1024)

#define B_TRUE                           1
#define B_FALSE                          0

#define FILE_THREAD      1
#define MAIN_THREAD      0

#define MAIN_IO_EXCEPTION 	1
#define FILE_IO_EXCEPTION 2
#define MAIN_COMPLETE 3
#define FILE_COMPLETE 4
#define FILE_START 5
#define MAIN_START 6
#define FILE_WAIT 7
#define NO_FILE_THREAD 8
#define NO_REDIVISION 9

#define FILE_NODE        1
#define SOCKET_NODE      0

#define CURL_TIMEOUT_MULTIRAT_READ 1
#define CURL_BLOCK_MULTIRAT_READ 2

#define MAIN_SOCK_READ_ACTIVE 1
#define MAIN_SOCK_READ_INACTIVE 0

#define SOCKET_NODE_FORCE_EXCEPTION 1
#define SOCKET_NODE_NORMAL_EXCEPTION 2
#define SOCKET_NORMAL_EXCEPTION 3

#define DIRECT_WRITE_HEADER "x-direct-write: yes"
#define DIRECT_WRITE_HEADER_LENGTH (strlen(DIRECT_WRITE_HEADER) + 2) /*Additional 2 is for \r\n*/

#define NOTI_TRIGGER "S"
#define NOTI_TRIGGER_LENGTH 1

#ifdef SB_LOG_SUPPORT
#ifndef LOG_TAG
/* This LOG_TAG should be defined before including dlog.h. Because dlog.h is using it. */
#define LOG_TAG "multirat"
#endif
#include <dlog.h>
#endif

#ifdef SB_LOG_SUPPORT
#define TIZEN_LOGD(fmt, args...)		LOGI(fmt, ##args)
#define SECURE_DB_INFO(fmt, args...)		SECURE_LOGI(fmt, ##args)
#define SECURE_DB_DEBUG(fmt, args...)		SECURE_LOGD(fmt, ##args)
#define SECURE_DB_WARN(fmt, args...)		SECURE_LOGW(fmt, ##args)
#define SECURE_DB_ERROR(fmt, args...)		SECURE_LOGE(fmt, ##args)
#else
#define TIZEN_LOGD(fmt, args...)		
#define SECURE_DB_INFO(fmt, args...)		
#define SECURE_DB_DEBUG(fmt, args...)		
#define SECURE_DB_WARN(fmt, args...)		
#define SECURE_DB_ERROR(fmt, args...)  
#endif


#ifdef SB_DETAIL_LOG_SUPPORT
#define TIZEN_D_LOGD(fmt, args...) LOGI(fmt, ##args)
#define SECURE_DB_D_LOGD(fmt, args...) SECURE_LOGI(fmt, ##args)

#else
#define TIZEN_D_LOGD(fmt, args...)
#define SECURE_DB_D_LOGD(fmt, args...) 
#endif

#define CLOSE_SOCKET(socket) \
{\
	if(socket > 2)\
	{\
	close(socket);\
	}\
	else\
	{\
		TIZEN_LOGD("Socket is Less Than 2 Value %d", socket);\
	}\
}\

typedef char            int8;
typedef unsigned char   uint8;
typedef int             int32;
typedef unsigned int    uint32;
typedef long long            int64;
typedef unsigned long long   uint64;


typedef enum
{
	HTTP_GET = 1,
	HTTP_POST,
	HTTP_HEAD
} eHTTPMsgType;

typedef enum
{
	HTTP_VERSION_1_0 = 1,
	HTTP_VERSION_1_1
}eHTTPVersion;

typedef struct _interfaceInfo_
{
	int8 interface_name[TMAX];
	int8 ip[INET_ADDRSTRLENG];
	int8 server_ip[INET_ADDRSTRLENG];
	int32 server_port ;
	int32 proxyEnable;
	int8 proxy_addr[INET_ADDRSTRLENG];
	int32 proxy_port;
	int8 dns_1[INET_ADDRSTRLENG];
	int8 dns_2[INET_ADDRSTRLENG];
}interfaceInfo;

typedef struct _connection_
{
	int32 port;
	int32 sockId[MAX_INTERFACES];
	int8 ip_addr[INET_ADDRSTRLENG];
	interfaceInfo ifaceInfo[MAX_INTERFACES];
	int32 ip_family;		/*  ip_family = 0 -> ipv4     1 -> ipv6  */
}connection;


typedef struct _httpResp_
{
	int8 resp_buff[MAX_HEADER_SIZE];
	int8 resp_buff_body[MAX_HEADER_SIZE];
	uint64 resp_header_length;
	int8 *http;
	int8 *rspcode;
	int8 *connection;
	int8 *contLen;
	int8 *contRange;
	int8 *accept_range;
	int8 *location;
	int32 acceptFlag;
	uint64 cLen;
	uint64 instanceSize;
}httpResp;

typedef struct _httpReq_
{
	eHTTPMsgType method;
	uint32 reqLen;
	uint32 req_wo_len;
	uint64 rangeStart;
	int8 *url;
	int8 *req_buff;
	int8 *req_buff_wo_range;
	int8 *accept_range;
	int8 *connection;
	int8 *contLen;
	int8 *Rangeheader;
	int8 *contType;
	int8 *ifRange;
	int8 *request[MAX_INTERFACES];
}httpReq;

typedef enum __State_
{
	STATE_NOT_READ = 1,
	STATE_OCCUPIED,
	STATE_READING,
	STATE_BLOCKED,
	STATE_FULL_READ,
	STATE_CLEARED
} eState;

typedef struct _DataBuffer_
{
	int32 threadId;
	int32 socketId;
	uint32 offset;
	uint32 totalLen;
	uint32 estSpeed;
	uint32 appReadLen;
	uint32 isContinueChunk;
	int8 *data;
	eState state;

	int8 filePath[200];
	FILE *readFp;   /* File pointer used only for reading */
	FILE *writeFp;  /* File Pointer used  only for writing */
	uint64 cthread;

	pthread_mutex_t mut;
}DataBuffer;

typedef struct _SmartBondingData_ SmartBondingData;

typedef struct _BlockManager_
{
	uint32 noOfChunks;
	uint32 chunkSize;
	uint32 lastChunkSize;
	uint32 minSizeToHandover;
	uint32 threadState[MAX_INTERFACES];
	uint32 noOfIOExp[MAX_INTERFACES];
	uint64 rspOffset;
	uint64 comRspLen;
	uint64 strtOffset;
	uint64 speed[MAX_INTERFACES];
	uint64 headerSpeed[MAX_INTERFACES];
	int32 prevChunkId[MAX_INTERFACES];
	int32 minNotReadChunkId;
	int32 *currentChunkId;
	pthread_mutex_t mutex;
	DataBuffer *commBuff;
	SmartBondingData *SBData;
}BlockManager;

typedef struct _StatDetails_
{
	uint32 speedIndex;
	uint32 mainSockSpeed;
	uint32 dataArr[100];
	uint64 timeT1;
	uint64 sendTime;
	uint64 offsetForSpeed;
	uint64 dataOffset;
	uint64 main_thread_sendTime;
	uint64 startTime;
	uint64 dataStrtTime;
	uint64 tempTime;
	uint64 dataOffsetTime;
	uint64 timeArr[100];
	uint64 read_start_time;
}StatDetails;

typedef struct _speedStat_
{
	uint32 prev_read;
	int32 prev_sock_read;
	uint64 recv_length[2];
	uint64 start_recv_time[2];
	uint64 minTimeToCheckStopSlow[2];
	uint64 prev_recv_time[2];
	uint64 slow_start_length[2];
	uint64 slow_start_time[2];
	uint64 start_speed_check_time;
	uint64 dataArray[2][MAX_HISTORY];
	uint64 timeArray[2];
}speedStat;

typedef struct _CThread_
{
	uint64 threadId;
	int32 threadStatus;
}CThread;


typedef struct _PollThread_
{
    uint64 threadId;
    int32 threadStatus;
}PollThread;

typedef struct _CURLThread__
{
	uint64 threadId;
	int32 threadStatus;
}curlThread;

typedef struct _RangeRequestThread_
{
	int32 socketId;
	int32 threadId;
	int32 firstRngStatus;
	uint32 headerLen;
	uint64 compRspLen;
	uint64 contRngLen;
	uint32 *compRspRcvdFlag;
	uint32 minBlockSize;
	uint32 maxBlockSize;
	uint32 speedTimeOut;
	uint32 minDataForSpeed;
	uint32 blockForSpeed;
	int8 *reqHeaders;
	connection *conn;
	pthread_t pThreadId;
	BlockManager *blockMgr;
	DataBuffer *commBuffer;
	SmartBondingData *SBData;
}RangeRequestThread;

typedef struct _MultiSocket_
{
	int32 currentChunkId;
	uint32 noOfChunks;
	uint32 appReadLen;
	uint32 compRspRcvdFlag;
	uint64 rspOffset;
	uint64 compRspLen;
	uint64 strtOffset;
	connection *conn;
	BlockManager *blockMgr;
	DataBuffer * commBuffer;
	RangeRequestThread *reqThread[MAX_INTERFACES];
	SmartBondingData *SBData;
}MultiSocket;

typedef enum __nodeState_
{
	NODE_STATE_NOT_READ = 1,
	NODE_STATE_DOWNLOADING,
	NODE_STATE_BLOCKED,
	NODE_STATE_FULL_READ,
	NODE_STATE_CLEARED
}nodeState;

typedef struct _fileBuffer_ fileBuffer;

struct _fileBuffer_
{
	int32 socketId; /* if not zero means current file buffer should be read from socket */
	uint32 nodeType;
	uint32 bRafMode;
	uint32 fThread_read;
	uint64 offset;
	uint64 startOffset;
	uint64 endOffset;
	uint64 totalLen;
	uint64 appReadLen;
	uint64 interface;
	uint64 file_flush_offset; /* Offset that is fflushed already */
	int8 filePath[200];
	FILE *readFp;   /* File pointer used only for reading */
	FILE *writeFp;  /* File Pointer used  only for writing */
	pthread_mutex_t mut;
	nodeState state;
	fileBuffer *next;
};

typedef struct _randomFileManager_
{
	uint32 rspHeaderCheck;
//	uint64 expectedBytes;
	uint64 rspRead;     	// for main thread response data count
	uint64 prevRange;
	SmartBondingData *SBData;
	FILE *writeFD1;
	FILE *writeFD2;

}randomFileManager;

typedef struct _fileManager_
{
	uint64 *ExpectedBytes;
	uint64 *rspRead;
	uint64 totalLen;
	uint64 strtOffset;
	uint32 thread_exception;
	uint32 interface[2];
	fileBuffer **fbuffer;
	pthread_mutex_t mutex;
	SmartBondingData *SBData;
}fileManager;

typedef struct _fileThread_
{
	pthread_t pthreadId;
	uint32 interface_index;
	uint32 headerLen;
	uint32 *compRspRcvdFlag;
	uint32 status;
	int32 socketId;
	int8 *req;
	uint32 firstRngStatus;
	uint64 compRspLen;
	uint64 contRngLen;
	fileManager *fileMgr;
	connection *conn;
	SmartBondingData *SBData;
}fileThread;

typedef struct _fileStream_
{
	uint64 *mainSockExpBytes;
	uint64 *mainSockRead;
	uint64 totalLen;
	uint64 strtOffset;
	uint32 compRspRcvdFlag;
	fileManager *fileMgr;
	fileBuffer *fileBuff;
	fileThread *fThread;
	SmartBondingData *SBData;
}fileStream;

typedef struct _fileCThread_
{
	uint64 threadId;
	int32 threadStatus;
}fileCThread;

struct _SmartBondingData_
{
	int32 socket_fd;
	uint32 user_option;
	uint32 dns;
	uint32 dns_iface;
	uint32 sync;
	uint32 cancel;
	uint32 curl;
	uint32 timeout;
	uint32 mainSockExp;
	uint32 interface_index;
	uint32 response_check;
	uint32 response_check_length;
	uint32 enableMultiRat;
	uint32 multiRatCheckDone;
	uint32 mSocketDataBufferReady;
	uint32 multiSocketThreadStarted;
	uint32 watch_dog_complete;
	uint64 response_body_read ;
	uint64 totalExpectedBytes;
	uint64 CurlStartTime ;
	httpReq req;
	httpResp resp;
	connection conn;
	StatDetails stat;
	CThread *cthread;
	curlThread *curlThrd;
	MultiSocket *msocket;
	pthread_mutex_t tempLock;

	PollThread *PollThrd;
	int32 trigger_pipefd[2];
	int32 noti_pipefd[2];
	uint32 poll_thread_noti_exception;
	uint32 Libfd;

	int32 con_status;
	int32  division_count;
	int32  read_state_check;        //Created to capture state of main read socket
	uint64 expectedbytes;
	uint32 fStreamFileBufferReady;
	uint32 fileThreadStarted;
	uint32 twoChunk;
	uint32 socket_check;
	uint32 testtime;
	uint32 testcount;
	uint32 status;
	uint32 file_status;
	uint32 node_exception;
	uint32 support_exception;
	fileStream *fStream;
	fileCThread *filecthread;
	speedStat sStat;
	uint32 speed[2];

	int8 FileData[100]; /* This Stores the Data to be sent to Curl For File Thread Progress */
	randomFileManager raFileMngr;
	int8 rafFileName[200];
	uint32 bRafMode ;	/* 1 if RAF mode is SET else 0 */
	uint32 resp_complete ; /* This Indicate that response is received and Decision on RAF is Done */
	uint64 content_length ;
	uint64 startOffset; /* Range Start Offset in Ranage Request Header */
};

typedef struct _MultiSockInput_
{
	uint32 chunkSize;
	uint32 noOfChunks;
	uint32 lastChunk;
	uint64 rspOffset;
	connection *conn;
}MultiSockInput;

#endif
