#ifndef DATABUFFER_H_
#define DATABUFFER_H_

#include "multirat_SB_http.h"

#define DATA_BUFFER_GET_STATE(a)        ((a)->state)
#define DATA_BUFFER_SET_STATE(a, b)     ((b)->state = a)
#define DATA_BUFFER_GET_BUFFER(a)       ((a)->data + a->offset)
#define DATA_BUFFER_GET_TOTAL_LEN(a)    ((a)->totalLen)
#define DATA_BUFFER_GET_READ_RES_LEN(a) ((a)->appReadLen)
#define DATA_BUFFER_GET_RES_BYTES(a)    ((a)->offset - (a)->appReadLen)
#define DATA_BUFFER_GET_OFFSET(a)       ((a)->offset)
#define DATA_BUFFER_GET_EST_SPEED(a)    ((a)->estSpeed)
#define DATA_BUFFER_GET_THREAD_ID(a)    ((a)->threadId)

/**
 * @brief                           initialize the data buffer
 * @param[in]          dbuffer      data buffer
 * @return                          void
 * @retval                          none
 */
void data_buffer_init(DataBuffer *dbuffer, uint32 noOfChunks, uint64 cthread);
/**
 * @brief                           free the memeory for buffer
 * @param[in]          dbuffer      data buffer
 * @return                          void
 */

void data_buffer_freeBuffer(DataBuffer *dbuffer);

/**
 * @brief                           reads the response from this buffer and
 *                                  increase the appReadLen
 * @param[in]         buff          application buffer
 * @param[in]         size          size of application buffer
 * @param[in]         dbuffer       data buffer
 * @return                          number of bytes read from this buffer
 */

void data_buffer_read_portion(int8 *buff, uint32 size, DataBuffer *dbuffer);

/**
 * @brief                           add the response to this data buffer
 * @param[in]          size         size of the response buffer
 * @param[in]          threadId     threadID from which data is to be added
 * @param[in]          dbuffer      data buffer
 * @return                          bytes written into this data buffer
 */

void data_buffer_add(uint32 size, int32 threadId, int8 *buff, DataBuffer *dbuffer);

/**
 * @brief                           called when current data buffer is to be
 *                                  handed over to other thread
 * @param[in]          threadId     thread ID to from which data is to be added
 * @param[in]          thisSpeed    other thread speed
 * @param[in]          dbuffer      data buffer
 * @return                          void
 */

void data_buffer_switch_socket(int32 threadId, uint32 thisSpeed,DataBuffer *dbuffer);
/**
 * @brief                           initialize data buffer and changes the state
 * @param[in]          threadId     thread ID to which  data buffer is assigned
 * @param[in]          size         total size of this data buffer
 * @param[in]          socketId     socket ID
 * @param[in]          dbuffer      data buffer
 * @return                          void
 */

void data_buffer_init_chunk(int32 threadId, uint32 size, int32 socketId, DataBuffer *dbuffer, int64 *chunkInfo);

/**
 * @brief                           resets the threadId and changes the state
 * @param[in]          threadId     threadID to which data buffer is assigned
 * @param[in]          socketId     socket ID
 * @param[in]          dbuffer      data buffer
 * @return                          void
 */

void data_buffer_reinit_chunk(int32 threadId,int32 socketId, DataBuffer *dbuffer);
/**
 * @brief                           destroy the mutex and frees the data buffer
 * @param[in]          dbuffer      data buffer
 * @return                          void
 */

void data_buffer_exit(DataBuffer *dbuffer);

#endif

