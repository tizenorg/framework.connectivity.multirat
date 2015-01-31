#ifndef BLOCKMANAGER_H_
#define BLOCKMANAGER_H_

#include "multirat_SB_http.h"

#define GET_OTHER_THREAD_ID(a)              (((a) + 1) % 2)
#define SET_SPEED(a, b, c)                  ((c)->speed[(a)] = (b))
#define SET_HEAD_SPEED(a, b, c)             ((c)->headerSpeed[a] = (b))

/**
 * @brief                           initialize the block manager
 * @param[in]         psBlkInfo     Block Manager Info Structure
 * @param[in]         bmanager      Block Manager Object
 * @return                          void
 * @retval                          None
 */
void block_manager_init(MultiSocket *mSocket, BlockManager *bmanager,MultiSockInput *mSockInput);

/**
 * @brief                            assign chunk for current thread
 * @param[in]           chunkInfo    chunkInformation
 * @param[in]           threadId     Thread Number
 * @param[in]           socketId     Socket Number
 * @param[in]           bmanager     Block Manager Object
 * @return                           status if chunk assigned
 * @retval              0            chunk assigned to thread
 * @retval
 */

int32 block_manager_get_next_chunk(int64 *chunkInfo,int32 threadId,int32 socketId,
		  BlockManager *bmanager);

/**
 * @brief                            get the minimum chunk which is unread
 * @param[in]          chunkId       chunkInformation
 * @param[in]          chunkInfo     chunkInformation
 * @param[in]          threadId      Thread Number
 * @param[in]          socketId      Socket Number
 * @param[in]          bmanager      Block Manager Object
 * @return                           void
 * @retval                           none
 * @retval                           none
 */
void block_manager_getmin_notread_chunk(int32 chunkId, int64 *chunkInfo, int32 threadId,
		  int32 socketId, BlockManager *bmanager);

/**
 * @brief                            min unread chunckID
 * @param[in]          bmanager      Block Manager Object
 * @return                           chunkID
 * @retval             chunkID       when successful
 * @retval             -1            on error
 */

int32 block_manager_getmin_notread_chunkId(BlockManager *bmanager);

/**
 * @brief                            min unread chunckID from last
 * @param[in]          bmanager      Block Manager Object
 * @return                           chunkID
 * @retval             chunckID      when successful
 * @retval             -1            on error
 */
int32 block_manager_get_lastmin_notread_chunkId(BlockManager *bmanager);

/**
 * @brief                            get the min chunkID which is unread
 * @param[in]          chunkId       chunkInformation
 * @param[in]          bmanager      Block Manager Object
 * @return                           unread chunkID
 * @retval             chunkID       when successful
 * @retval             0             on error
 */
int32 block_manager_get_min_not_read_jump_case(int32 chunkId,BlockManager *bmanager);

/**
 * @brief                            Gets next chunkId where request thread
 *                                   speed is slower than other thread speed
 * @param[in]          ratio         Ratio of speed for both interfaces
 * @param[in]          otherId       Thread ID of Other Thread
 * @param[in]          bmanager      Block Manager Object
 * @return                           chunkID
 * @retval             chunkID       when successful
 * @retval
 */
int32 block_manager_handle_slow_case(uint32 ratio, uint32 otherId,BlockManager *bmanager);

/**
 * @brief                            Gets next chunkId where request thread
 *                                   speed is faster than other thread speed
 * @param[in]          ratio         Ratio of both the interfaces speeds
 * @param[in]          thisSpeed     Request thread Speed
 * @param[in]          otherSpeed    Speed of other thread
 * @param[in]          otherBuff     Other Thread last chunk info(data buffer)
 * @param[in]          otherId       ThreadID of other thread
 * @param[in]          threadId      Current thread ID
 * @param[in]          bmanager      Block Manager Object
 * @return                           chunkID
 * @retval             chunkID       chunkID when successful
 * @retval
 */
int32 block_manager_handle_fastcase(uint32 ratio, uint64 thisSpeed, uint64 otherSpeed,
		  DataBuffer *otherBuff, uint32 otherId, int32 threadId, BlockManager *bmanager);

/**
 * @brief                            Reset the previous ChunkID
 * @param[in]          threadId      Thread number
 * @param[in]          chunkId       Chunk Information
 * @param[in]          bmanager      Block Manager Object
 * @return                           void
 */
void block_manager_io_exception(int32 threadId, int32 chunkId,BlockManager *bmanager);


/**
 * @brief                            Check the status of other thread
 *                                   downloading chunks
 * @param[in]          threadId      Thread number
 * @param[in]          chunkId       Chunk Information
 * @param[in]          bmanager      Block Manager Object
 * @return                           status of block manager chunk
 * @retval             1             block manager chunk is blocked
 * @retval             0             no chunk blocked
 */
uint32 block_manager_checkOtherThread(int32 threadId, int32 chunkId, BlockManager *bmanager, uint32 temp_check);

/**
 * @brief                            Checks the common buffer status by
 *                                   checking each data buffer state
 * @param[in]          bmanager      Block Manager Object
 * @return                           status of common buffer
 * @retval             1             wait till app reads some data
 * @retval             0             ready to download next chunk
 */
int32 block_manager_check_buffer_status(BlockManager *bmanager);


/**
 * @brief                            Checks the state if any buffer is still downloading
 *                                   thread should not exit
 * @param[in]          bmanager      Block Manager Object
 * @param[in]          threadId      Thread number
 * @return                           thread status
 * @retval             1             Thread can exit
 * @retval             0             Thread should not exit
 */
int32 block_manager_checkAllBufferStatus(BlockManager *bmanager,int32 threadId);

/**
 * @brief                            if block manager has chunk in not read or
 *                                   blocked state
 * @param[in]          bmanager      Block Manager Object
 * @return                           status of block manager
 * @retval             1             has chunks in blocked or unread state
 * @retval             0             no chunks in blocked or unread state
 */
int32 block_manager_chunk_present(BlockManager *bmanager);

/**
 * @brief                            Destroy the mutex
 * @param[in]          bmanager      Block Manager Object
 * @return                           void
 * @retval                           none
 */
void  block_manager_exit(BlockManager *bmanager);

/**
 * @brief                            Check speed of interface in current thread
 * @param[in]          bmanager      Block Manager Object
 * @param[in]          threadId      Thread number
 * @return                           thread status
 * @retval             0             thread wait
 * @retval             2             thread continue
 */

uint32  block_manager_checkSpeed(BlockManager *bmanager,int32 threadId);

/**
 * @brief                            stops thread during extreme condition
 * @param[in]          chunkInfo     chunk information
 * @param[in]          threadId      thread number
 * @param[in]          socketId      socket number
 * @param[in]          bmanager      block manager object
 * @param[in]          otherBuff     data buffer
 * @param[in]          otherId       other thread id
 * @param[in]          this speed    speed of current thread interface
 * @return                           void
 * @retval                           none
 */
void block_manager_handleExtermeCase(int64 *chunkInfo, int32 threadId, int32 socketId,
		  BlockManager *bmanager, DataBuffer *otherBuff,uint32 otherId,uint64 thisSpeed);
/**
 * @brief                            get continious chunk information
 * @param[in]          chunkInfo     chunk information
 * @param[in]          threadId      thread number
 * @param[in]          socketId      socket number
 * @param[in]          bmanager      block manager object
 * @return                           void
 */

void block_manager_getContinueChunk(int64 *chunkInfo, int32 threadId, int32 socketId,
		  BlockManager *bmanager);
/**
 * @brief                            buildContChunk
 * @param[in]          chunkId       chunk number
 * @param[in]          startOffset
 * @param[in]          chunkInfo     chunk information
 * @param[in]          threadId      thread number
 * @param[in]          socketId      socket number
 * @param[in]          bmanager      Block Manager Object
 * @return                           void
 */

void buildContChunk(int32 chunkId,uint64 startOffset, int64 *chunkInfo,int32 threadId,
		  int32 socketId, BlockManager *bmanager);
/**
 * @brief                            check for continious chunk in block manager
 * @param[in]          bmanager      Block Manager Object
 * @return                           status for continious chunk
 * @retval             1             continious chunk present
 * @retval             0             continious chunk not present
 */

int32 block_manager_isContChunkPresent(BlockManager *bmanager);

int32 get_interface_id(int32 threadId);

#endif /* BLOCKMANAGER_H_ */

