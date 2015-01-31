#ifndef RANGEREQUESTTHREAD_H_
#define RANGEREQUESTTHREAD_H_

#include <pthread.h>

#define CHUNK_INFO_SIZE                         3
#define MAX_HEADERS_SIZE                        2048
#define MAX_RANGE_FIELD_LEN                     100

#define FIRST_RSP_STATUS_SUCCESS                0
#define FIRST_RSP_STATUS_PENDING                -2
#define FIRST_RSP_STATUS_FAILED                 -1

#define RANGE_REQUEST_THREAD_GET_FIRST_RANGE_STATUS(a) ((a)->firstRngStatus)

/**
 * @brief                            initialization of range request thread
 * @param[in]           rrthread     range request thread
 * @param[in]           threadData   threadData object
 * @return                           void
 */

void range_request_thread_init(RangeRequestThread *rrthread, SmartBondingData *SBData);

/**
 * @brief                           start the range request thread
 * @param[in]           rrthread    range request thread object
 * @return                          status if thread is started
 * @retval              1           range request thread created
 * @retval              0           error creating range request thread
 */

uint32 range_request_thread_start(RangeRequestThread *rrthread);

/**
 * @brief                           callback function while creating rr thread
 * @param[in]           pArg        arguments passed in callback function
 * @return                          NULL
 */

void *range_request_thread_rngreq_thread_callback(void *pArg);

/**
 * @brief                           range request thread run
 * @param[in]           rrthread    range request thread object
 * @return                          void
 */

void range_request_thread_run(RangeRequestThread *rrthread);

/**
 * @brief                           range_request_thread_reconnect
 * @param[in]           newRequest  object to store new request
 * @param[in]           chunkInfo   chunk information
 * @param[in]           rrthread    range request thread
 * @return                          range length and header length
 */

uint32 range_request_thread_rebuild_req(int8 *newRequest, int64 *chunkInfo,
		  RangeRequestThread *rrthread);

/**
 * @brief                           exit the range request thread
 * @param[in]           rrthread    range request thread object
 * @return                          void
 */

void range_request_thread_exit(RangeRequestThread *rrthread);

/**
 * @brief                           process range request response headers
 * @param[in]           socket_fd   socket file_descriptor
 * @param[in]           size        size
 * @param[in]           timeout     timeout for socket polling
 * @param[in]           instanceSize size of response instance
 * @param[in]           currChunkLen currChunkLen
 * @param[in]           bodylen     response body length
 * @param[in]           blocksize   blocksize
 * @param[in]           respLen     length of response
 * @return                          response decode status
 * @retval              0           http response decoding success
 * @retval              -1          http response decoding error
 * @retval              -2          http response socket error
 */

int32 range_request_recv_rng_rsp_headers(int32 socket_fd, uint32 size, uint32 timeout, uint64 instanceSize,
		  uint64 currChunkLen, int32 *bodyLen, int8 *blockSize, uint64 respLen, uint32 *connClose);
/**
 * @brief                            validate range request response
 * @param[in]          instanceSize  instance size
 * @param[in]          httpRsp       http response
 * @param[in]          currChunkLen  current chunk len
 * @param[in]          respLen       response length
 * @return                           response decode status
 * @retval             -1            http response decoding error
 * @retval             0             http response decoding success
 */

int32 range_request_validate_rsp(uint64 instanceSize, httpResp *httpRsp,
		  uint64 currChunkLen, uint64 respLen, uint32 *connClose);

#endif /* RANGEREQUESTTHREAD_H_ */

