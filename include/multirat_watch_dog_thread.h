#ifndef MULTIRAT_WATCH_DOG_H_
#define MULTIRAT_WATCH_DOG_H_

#include "multirat_SB_http.h"
#include "multirat_connection.h"

typedef enum  {
	 THREAD_INIT = 0,
	 THREAD_RUNNING,
	 THREAD_FINISH
}THREAD_STATUS;

/*struct http_sample  {
  char *request;
  int length;
  }; */

/**
 * @brief                           initialize cthread
 * @param[in]         void
 * @return
 */

CThread * cthread_init(void);

/**
 * @brief                            thread function running
 * @param[in]           cthread      CThread object
 * @return
 * @retval
 * @retval
 */

void cthread_run_thread(SmartBondingData *SBData);

/**
 * @brief                           get the bytes from range request header
 * @param[in]           start       buffer to store the bytes
 * @param[in]           rangeHeader rangeHeader to decode
 * @return                          bytes of range request
 * @retval              1           bytes updated in param start
 * @retval              0           error
 */

int32 get_bytesof_range_request(uint64 *start, int8 *rangeHeader);

/**
 * @brief                           check if connection is keep-alive
 * @param[in]           SBData      Smart bonding object
 * @return                          status of connection
 * @retval              1           connection header is keep alive
 * @retval              0           connection header is not keep alive
 */

int32 is_connection_header_keepalive(SmartBondingData *SBData);

/**
 * @brief                            start the watch_dog_thread
 * @param[in]         cthread        cthread object
 * @return                           void
 */

void cthread_start_thread(SmartBondingData *SBData);

/**
 * @brief                           watch dog thread entry function
 * @param[in]         pArg          cthread entry params
 * @return                          void
 */
void * cthread_entry_function (void *pArg);

/**
 * @brief                           check the status of the thread
 * @param[in]         cthread       cthread object
 * @return                          status of cthread
 * @return             0            thread init
 * @retval             1            thread running
 * @retval             2            thread finish
 */
int32 cthread_get_thread_status(CThread *cthread);

/**
 * @brief                           exit the watch dog thread
 * @param[in]         cthread       cthread object
 * @return                          void
 */
void cthread_exit(CThread *cthread);

/**
 * @brief                            creat,bind and check the watch dog thread
 * @param[in]           SBData       smartbonding data object
 * @return                           status of connection
 * @retval              0            successful connection
 * @retval              -1           error
 */
int32 watchdog_test_connection_type(SmartBondingData *SBData);

/**
 * @brief                            calculate no of chunks in watchdog thread
 * @param[in]           chunkSize    chunk size
 * @param[in]           noOfChunks   total no of chunks
 * @param[in]           lastChunk    last chunk
 * @param[in]           totalSize    total size
 * @return                           void
 */
void multirat_watchdogthread_calnochunks(uint32 chunkSize,uint32 *noOfChunks,uint32 *lastChunk,uint64 totalSize);

/**
 * @brief                            get request without range from range header
 * @param[in]           oldReq       old request
 * @param[in]           newReq       new request
 * @param[in]           rangeHeader  rangeHeader
 * @param[in]           rangeStart   range start buffer
 * @return                           status of getting request from header
 * @retval              1            successfully removed range header
 * @retval              0            copied old request to new request
 * @retval              -1           unseccessful decoding of range request
 */
int32 get_req_without_range(int8 *oldReq, int8 *newReq, int8 *rangeHeader, uint64 *rangeStart);

int32 check_speed(SmartBondingData *SBData, uint32 timeT2, uint32 resp_offset,
                              uint32 resp_len, int8 *recv_buf, int32 socket, uint64 contLength);

void switch_to_watchdog(SmartBondingData *SBData, uint32 resp_offset, uint32 resp_len, int8 *recv_buf, int32 socket);

void file_cthread_run_thread(SmartBondingData *SBData);

int32 file_thread_FirstConnection(SmartBondingData *SBData, fileThread *fThread, int64 *chunkInfo, int8 *recv_buf, int32 *lengthRcvd);

#endif
