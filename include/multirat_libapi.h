#ifndef _MULTIRAT_LIBAPI_H
#define _MULTIRAT_LIBAPI_H
#include <pthread.h>
#include "multirat_SB_http.h"

#define SB_OK                                         -2
#define SB_WOULD_BLOCK                                -3
#define SB_ERR                                        -4
#define SB_EOF                                        -5
#define SB_TIMEOUT                                    -6

#define CONNECTION_SUCCESS 1
#define CONNECTION_FAIL 0
#define CONNECTION_WAIT 2


#define MSG_POLL_THREAD_START_SOCK                     "SOCKET_POLL_START"
#define LEN_MSG_POLL_THREAD_START_SOCK                 17
#define MSG_POLL_THREAD_START_BUFF                     "BUFFER_POLL_START"
#define LEN_MSG_POLL_THREAD_START_BUFF                 17
#define MSG_POLL_THREAD_START_EXCEPTION                "EXCEPTION_POLL_START"
#define LEN_MSG_POLL_THREAD_START_EXCEPTION            20
#define MSG_POLL_THREAD_END                            "POLL_END"
#define LEN_MSG_POLL_THREAD_END                        8
#define RECV_BUFF_SIZE                                 20
#define POLL_TIME_OUT_MILLISEC                         100
#define END_OF_HEADER                                  "\r\n\r\n"

struct SmartBondingHandler
{
	 /* Session Identifier for SB Library */
	 SmartBondingData *SBData;
	 /* Session Identifier for HTTP Library used for callbacks and closing */
	 void *LibSessionIdentifier;
	 pthread_mutex_t *lock; /* Mutex Lock for sb_read_data and sb_session_close */
};

/**
 * @brief                                    Library api to get chunk stored currently in RAF
 * @param[in]           SBHandler            struct SmartBondingHandler
 * @param[in]           buffer               currenly written files startOffset-EndOffset
 * @param[in]           len                  length of buffer
 * @return              1
 * @return              0
*/

uint32 sb_get_cached_chunk(struct SmartBondingHandler *SBHandler, int8* buffer, uint32 len);

/**
 * @brief                                    Library api to set RAF file name
 * @param[in]           SBHandler            struct SmartBondingHandler
 * @param[in]           buffer               file name of RAF
 * @param[in]           len                  length of file name
 * @return              1					 file name set
 * @return              0                    file name setting failed
*/

uint32 sb_set_direct_filename(struct SmartBondingHandler *SBHandler, int8 *buffer, uint32 len);


/**
 * @brief                                    Library api to set RAF mode
 * @param[in]           SBHandler            struct SmartBondingHandler
 * @return              void
*/

void sb_set_direct_write_mode(struct SmartBondingHandler *SBHandler);

/**
 * @brief                                    Library api to send request to server,
 checks for multirat condition and enables multirat
 * @param[in]    http_req                    req to be sent to http server
 * @param[in]    timeout                     timeout to connect server
 * @param[in]    remote_info                 destinatopn server address
 * @param[in]    LibraryCallbackFunction     Lib API callback function
 * @param[in]    LibSessionIdentifier
 * @return       struct SmartBondingHandler  SBHandler
 */

struct SmartBondingHandler *sb_request_send(int8 *http_req, uint32 timeout,
		  struct sockaddr_storage *remote_info, void (*LibraryCallbackFunction)(void *),
		  void *LibSessionIdentifier);

/**
 * @brief                                    Library api to send request to server,
 checks for multirat condition and enables multirat in sync case
 * @param[in]    http_req                    req to be sent to http server
 * @param[in]    timeout                     timeout to connect server
 * @param[in]    remote_info                 destination server address
 * @return       SmartBondingHandler  SBHandler
 */

struct SmartBondingHandler *sb_request_send_sync(int8 *http_req, uint32 timeout,
		  struct sockaddr_storage *remote_info);

/**
 * @brief                                    Library api to send request to server,
 checks for multirat condition and enables multirat in curl case
 * @param[in]    http_req                    req to be sent to http server
 * @param[in]    timeout                     timeout to connect server
 * @param[in]    remote_info                 destination server address
 * @return       struct SmartBondingHandler  SBHandler
 */
struct SmartBondingHandler *sb_request_send_curl(int8 *http_req, uint32 timeout,
		  struct sockaddr_storage *remote_info);


/**
 * @brief                                    Library api call to read response from server
 * @param[in]           SBHandler            struct SmartBondingHandler
 * @param[in]           buffer               buffer is used to store response
 * @param[in]           size                 length of buffer to be read
 * @param[in]           nread                length of response read
 * @retval              SB_ERR               returns error in error case
 * @retval              SB_WOULD_BLOCK       if need to wait to read data
 * @retval              SB_OK                if data is read successfully
 * @retval              SB_EOF               if complete data is read
 */
int32 sb_read_data(struct SmartBondingHandler *SBHandler, int8 *buffer, uint32 size, int32 *nread);


/**
 * @brief                                    Library api to close the session
 * @param[in]           SBHandler            struct SmartBondingHandler
 * @return              true or false
 * @retval              0                    if SBHandler is NULL
 * @retval              1                    if successfully session is closed
 */
int32 sb_session_close(struct SmartBondingHandler *SBHandler);


/**
 * @brief                                    Initializes SmartBondingHandler structure
 * @param[in]
 * @return              SmartBondingHandler
 */
struct SmartBondingHandler *smart_bonding_handler_init(void);


/**
 * @brief                                    Deinitializes SmartBondingHandler and
 SmbSessionIdentifier structure
 * @param[in]           SBHandler
 * @return              void
 */
void smart_bonding_handler_exit(struct SmartBondingHandler *SBHandler);


/**
 * @brief                                    Deinitializes SmbSessionIdentifier
 structure
 * @param[in]           SBSessionIdentifier
 * @return              void
 */
void smart_bonding_session_identifier_exit(SmartBondingData *SBData);


/**
 * @brief                                    poll thread which calls pollthread_run
 * @param[in]           SBHandler
 * @return              void
 */
void * poll_thread_call_back(void *pArg);


/**
 * @brief                                    poll thread to poll on socket or
 on common buffer to check for data
 * @param[in]           SBHandler
 * @return              void
 */
void pollthread_run(SmartBondingData *SBData);


/**
 * @brief                                    reads data from server
 * @param[in]           socket_fd            socket fd
 * @param[in]           buffer               buffer to store response
 * @param[in]           size                 size of buffer
 * @param[in]           my_nread             length of response received
 * @param[in]           SBSessionIdentifier  SB Session Identifier
 * @retval              SB_ERR               returns error in error case
 * @retval              SB_WOULD_BLOCK       if need to wait to read data
 * @retval              SB_OK                if data is read successfully
 * @retval              SB_EOF               if complete data is read
 */
int32 read_from_socket_async(int8 *buffer, uint32 size , int32 *my_nread, SmartBondingData *SBData);


/**
 * @brief                                     reads data from server in sync case
 * @param[in]           socket_fd             socket fd
 * @param[in]           buffer                buffer to store response
 * @param[in]           size                  size of buffer
 * @param[in]           my_nread              length of response received
 * @param[in]           SBSessionIdentifier   SB Session Identifier
 * @retval              SB_ERR                returns error in error case
 * @retval              SB_WOULD_BLOCK        if need to wait to read data
 * @retval              SB_OK                 if data is read successfully
 * @retval              SB_EOF                if complete data is read
 */
int32 read_from_socket_sync(int8 *buffer, uint32 size , int32 *my_nread, SmartBondingData *SBData);


/**
 * @brief                                     reads data from server in curl case
 * @param[in]           socket_fd             socket fd
 * @param[in]           buffer                buffer to store response
 * @param[in]           size                  size of buffer
 * @param[in]           my_nread              length of response received
 * @retval              SB_ERR                returns error in error case
 * @retval              SB_WOULD_BLOCK        if need to wait to read data
 * @retval              SB_OK                 if data is read successfully
 * @retval              SB_EOF                if complete data is read
 */
int32 read_from_socket_curl(int8 *buffer, uint32 size ,int32 *my_nread, SmartBondingData *SBData);


/**
 * @brief                                     check if multiple interfaces are available,
 and send range request to server
 * @param[in]           SBSessionIdentifier
 * @retval              0                     on failure
 * @retval              1                     on success
 */
int32 checkinterface_connect(SmartBondingData *SBData);


/**
 * @brief                                     Check whether server supports Range headers,
 and get request without range header
 * @param[in]           SBSessionIdentifier
 */
void main_socket_go_for_exception(SmartBondingData *SBData);


/**
 * @brief                                     Receives request from Library API call,
 initializes all required structures and send request to server
 * @param[in]           http_req              http request received from client
 * @param[in]           timeout               timeout to connect to the server
 * @param[in]           remote_info           remote server details like ip and port
 * @retval              SmartBondingHandler
 */
struct SmartBondingHandler *send_request(int8 *http_req, uint32 timeout, struct sockaddr_storage *remote_info);

/**
 * @brief                                       Handles creation of poll thread, and
 setting callback functions in async case
 * @param[in]           SBHandler               Library Handler
 * @param[in]           LibraryCallbackFunction Lib callback function
 * @param[in]           LibSessionIdentifier    Lib Session callback function
 * @return              true or false
 * @retval              1                       on failure
 * @retval              0                       on success
 */

int32 sb_init_async(struct SmartBondingHandler *SBHandler,
		  void (*LibraryCallbackFunction)(void *), void *LibSessionIdentifier);
void get_client_socket(SmartBondingData *SBData, uint32 timeout, struct sockaddr_in *serv_addr,struct sockaddr_in6 *serv_addr_ip6);
int32 read_from_socket(SmartBondingData *SBData,int8 *buffer, int32 size, int32 *my_nread);
int32 handleMainSocExp(SmartBondingData *SBData, int8 *buffer, uint32 size, int32 *my_nread);


int32 sb_request_send_only_curl(struct SmartBondingHandler * SBHandler, int8 *http_req, uint32 len);
struct SmartBondingHandler *curl_connect_request(uint32 timeout, struct sockaddr_storage *remote_info);
struct SmartBondingHandler *sb_request_connect_only_curl(uint32 timeout, struct sockaddr_storage *remote_info);
int32 sb_get_connection_status(struct SmartBondingHandler *SBHandler);

int32 twoChunk_read_from_socket(SmartBondingData *SBData,int8 *buffer, int32 size, int32 *my_nread);


#endif
