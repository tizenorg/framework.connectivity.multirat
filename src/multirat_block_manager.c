#include "multirat_data_buffer.h"
#include "multirat_conf.h"
#include "multirat_block_manager.h"
#include "multirat_process.h"

void block_manager_init(MultiSocket *mSocket, BlockManager *bmanager,MultiSockInput *mSockInput)
{
	uint32 i = 0;
	bmanager->chunkSize = mSockInput->chunkSize;
	bmanager->noOfChunks = mSocket->noOfChunks;
	bmanager->comRspLen = mSocket->compRspLen;
	bmanager->rspOffset = mSocket->rspOffset;
	bmanager->strtOffset = mSocket->strtOffset;
	bmanager->lastChunkSize = mSockInput->lastChunk;
	bmanager->minSizeToHandover = MIN_SIZE_TO_HANDOVER;
	bmanager->minNotReadChunkId = 0;
	bmanager->currentChunkId = &(mSocket->currentChunkId);

	/* Initialize of previousChunkID array */
	for (i = 0; i<MAX_INTERFACES ; i++)
	{
		bmanager->prevChunkId[i] = -1;
		bmanager->speed[i] = 0;
		bmanager->headerSpeed[i] = 0;
		bmanager->threadState[i] = STATE_THREAD_RUNNING;
		bmanager->noOfIOExp[i] = 0;
	}/* End of for */

	/* Copy the common buffer pointer */
	bmanager->commBuff = mSocket->commBuffer;

	/* Initialize mutex for calculating next HTTP Chunk */
	pthread_mutex_init(&(bmanager->mutex),NULL);

	return;
}

int32 block_manager_get_next_chunk(int64 *chunkInfo, int32 threadId, int32 socketId,
														BlockManager *bmanager )
{
	int32 chunkId = 0;
	uint32 ratio = 0;
	uint32 otherId = 0;
	uint64 thisSpeed = 0;
	uint64 otherSpeed = 0;
	DataBuffer *thisBuff = NULL;
	DataBuffer *otherBuff = NULL;

	TIZEN_D_LOGD("starts ...");

	pthread_mutex_lock(&bmanager->mutex);

	if(bmanager->threadState[threadId] == STATE_THREAD_STOPPED)
	{
		pthread_mutex_unlock(&bmanager->mutex);
		chunkInfo[2] = -1;
		return 0;
	}
	otherId = GET_OTHER_THREAD_ID(threadId);

	if(bmanager->threadState[otherId] == STATE_THREAD_STOPPED)
	{
		block_manager_getContinueChunk(chunkInfo,threadId,socketId,bmanager);
		pthread_mutex_unlock(&bmanager->mutex);
		return 0;
	}
	if ((bmanager->prevChunkId[threadId] == -1) ||
			(bmanager->prevChunkId[otherId] == -1))
	{
		/* assigning chunk first time to this thread */
		if (DATA_BUFFER_GET_STATE((bmanager->commBuff + threadId)) ==  STATE_NOT_READ)
		{
			chunkId = threadId;
			bmanager->minNotReadChunkId = chunkId + 1;
		}
		else
		{
			chunkId = block_manager_getmin_notread_chunkId(bmanager);
		}
		if(-1 != chunkId)
		{
			block_manager_getmin_notread_chunk(chunkId, chunkInfo,threadId, socketId, bmanager);
			bmanager->prevChunkId[threadId] = chunkId;
		}/* End of if */
		else
		{
			chunkInfo[2] = chunkId;
		}
		pthread_mutex_unlock(&bmanager->mutex);
		return 0;
	}/* End of if */

	thisBuff = bmanager->commBuff + bmanager->prevChunkId[threadId];
	otherBuff = bmanager->commBuff + bmanager->prevChunkId[otherId];

	thisSpeed = bmanager->speed[threadId];
	if (DATA_BUFFER_GET_THREAD_ID(thisBuff) != threadId)
	{
		/* Socket handover case */
		TIZEN_D_LOGD("socket handover case");
		otherSpeed = DATA_BUFFER_GET_EST_SPEED(thisBuff);
	} /* End of if */
	else
	{
		otherSpeed = bmanager->speed[otherId];
	} /* End of else */

	if(getTempLevel(bmanager->SBData))
	{
		if(thisSpeed > (1.5 * otherSpeed))
		{
			TIZEN_LOGD("Stopping other thread due to temp condition");
			block_manager_handleExtermeCase(chunkInfo,threadId,socketId,bmanager,otherBuff,otherId,thisSpeed);
		}
		else
		{
			TIZEN_LOGD("Stopping Current thread due to temp condition");
			bmanager->threadState[threadId] = STATE_THREAD_STOPPED;
			chunkInfo[2] = -1;
		}
		pthread_mutex_unlock(&bmanager->mutex);
		return 0;
	}

	if ((thisSpeed != 0))
	{
		TIZEN_LOGD("thread Id = %d  thisSpeed = %llu otherSpeed = %llu ",threadId, thisSpeed, otherSpeed);
		if (thisSpeed > otherSpeed)
		{
			//ratio = thisSpeed/otherSpeed;
			if ((otherSpeed == 0) || (((thisSpeed > (5 * otherSpeed)) || (bmanager->noOfIOExp[otherId] > 2)) &&
					(bmanager->prevChunkId[threadId] < bmanager->prevChunkId[otherId])))
			{
				//ratio = 100;
				TIZEN_LOGD("handleExtermeCase threadId %d otherId %d Exp %d",
						threadId,otherId,bmanager->noOfIOExp[otherId]);
				block_manager_handleExtermeCase(chunkInfo,threadId,socketId,bmanager,otherBuff,otherId,thisSpeed);
				pthread_mutex_unlock(&bmanager->mutex);
				return 0;
			}/* End of if */
			else
			{
				ratio = thisSpeed/otherSpeed;
			}/* End of else */
			chunkId = block_manager_handle_fastcase(ratio, thisSpeed,
					otherSpeed, otherBuff, otherId, threadId, bmanager);
		}/* End of if */
		else
		{
			ratio = otherSpeed/thisSpeed;
			chunkId = block_manager_handle_slow_case(ratio, otherId,bmanager);
		}/* End of else */
	}/* End of if */
	else
	{
		chunkId = block_manager_getmin_notread_chunkId(bmanager);
	}/* End of else */
	if(chunkId != -1)
	{
		block_manager_getmin_notread_chunk(chunkId, chunkInfo, threadId,socketId, bmanager);
		bmanager->prevChunkId[threadId] = chunkId;
	}/* End of if */
	else
	{
		chunkInfo[2] = chunkId;
	}
	pthread_mutex_unlock(&bmanager->mutex);
	return 0;
}/* End of getNextChunk() */

void block_manager_handleExtermeCase(int64 *chunkInfo, int32 threadId, int32 socketId,
						BlockManager *bmanager, DataBuffer *otherBuff,uint32 otherId,uint64 thisSpeed)
{
	bmanager->threadState[otherId] = STATE_THREAD_STOPPED;
	data_buffer_switch_socket(threadId,thisSpeed,otherBuff);
	TIZEN_D_LOGD("Min Chunk %d Prev Chunk %d",bmanager->minNotReadChunkId, bmanager->prevChunkId[otherId]);
	bmanager->minNotReadChunkId = MIN(bmanager->minNotReadChunkId, bmanager->prevChunkId[otherId]);
	block_manager_getContinueChunk(chunkInfo,threadId,socketId,bmanager);
}/* End of block_manager_handleExtermeCase() */


void block_manager_getContinueChunk(int64 *chunkInfo, int32 threadId,
																int32 socketId, BlockManager *bmanager)
{
	int32 chunkId = 0;
	uint32 state = 0;
	uint32 startOffset = 0;
	DataBuffer *blockChunk = NULL;

	if(block_manager_isContChunkPresent(bmanager))
	{
		state = DATA_BUFFER_GET_STATE(bmanager->commBuff + bmanager->minNotReadChunkId);
		if(state == STATE_BLOCKED)
		{
			blockChunk = (bmanager->commBuff + bmanager->minNotReadChunkId);
			blockChunk->totalLen = blockChunk->offset;
			blockChunk->state = STATE_FULL_READ;
			startOffset = blockChunk->totalLen;
			chunkId = bmanager->minNotReadChunkId + 1;
			bmanager->minNotReadChunkId = chunkId;
			//added newly
			blockChunk = (bmanager->commBuff + bmanager->minNotReadChunkId);
			blockChunk->totalLen = 0;
		}
		else if ((state == STATE_CLEARED) || (state == STATE_FULL_READ))
		{
			chunkId = bmanager->minNotReadChunkId + 1;
		}
		else
		{
			chunkId = bmanager->minNotReadChunkId;
		}
		TIZEN_LOGD("Continuous chunk present %d startOffset %d",chunkId,startOffset);
		bmanager->threadState[threadId] = STATE_THREAD_STOPPED;
		blockChunk = (bmanager->commBuff + chunkId);
		blockChunk->isContinueChunk = 1;
		blockChunk->threadId = get_interface_id(threadId);
		chunkInfo[2] = -1;
	}
	else
	{
		TIZEN_LOGD("getContinueChunk no continous chunk");
		chunkId = block_manager_getmin_notread_chunkId(bmanager);
		if(-1 != chunkId)
		{
			block_manager_getmin_notread_chunk(chunkId, chunkInfo,threadId,socketId, bmanager);
			bmanager->prevChunkId[threadId] = chunkId;
		}
		else
		{
			chunkInfo[2] = chunkId;
		}
	}/* End of else */
	return;
}/* End of  block_manager_getContinueChunk() */


int32 get_interface_id(int32 threadId)
{
	int8 *default_iname = DEFAULT_INTERFACE;
	if (0 == strncasecmp(default_iname, "lte", strlen("lte")))
	{
		return (threadId +1) % 2;
	}
	else
	{
		return threadId;
	}
}

int32 block_manager_isContChunkPresent(BlockManager *bmanager)
{
	uint32 i = 0;
	uint32 state = 0;

	if(bmanager->minNotReadChunkId == bmanager->noOfChunks - 1)
	{
		TIZEN_D_LOGD("Min Chunk %d",bmanager->minNotReadChunkId);
		return B_FALSE;
	}


	for (i = bmanager->minNotReadChunkId;i < bmanager->noOfChunks;i++)
	{
		state = DATA_BUFFER_GET_STATE(bmanager->commBuff + i);
		TIZEN_D_LOGD("State of Chunk %d %d",i,state);
		if (state == STATE_NOT_READ)
		{
			continue;
		}/* End of if */
		else if ((state == STATE_BLOCKED) && (i == bmanager->minNotReadChunkId))
		{
			continue;
		}/* End of else if */
		else if(((state == STATE_CLEARED) ||
				(state == STATE_FULL_READ)) && (i == bmanager->minNotReadChunkId))
		{
			continue;
		}/* End of else if */
		else
		{
			return B_FALSE;
		}/* End of else */
	}/* End of for */
	return B_TRUE;
}/* block_manager_isContChunkPresent */


int32 block_manager_handle_fastcase(uint32 ratio, uint64 thisSpeed, uint64 otherSpeed,
						DataBuffer *otherBuff,uint32 otherId,int32 threadId,BlockManager *bmanager)
{
	int32 chunkId = 0;

	TIZEN_D_LOGD("block_manager_handle_fastcase\n");
	chunkId = block_manager_getmin_notread_chunkId(bmanager);

	if (-1 != chunkId)
	{
		if (ratio > 10)
		{
			uint32 remLen = (DATA_BUFFER_GET_TOTAL_LEN(otherBuff) -
					DATA_BUFFER_GET_OFFSET(otherBuff)) * 8;
			if ((chunkId > bmanager->prevChunkId[otherId]) && (remLen > (bmanager->minSizeToHandover * 8)))
			{
				if ((otherSpeed == 0)  ||
						((otherSpeed != 0) && ((remLen/thisSpeed) + bmanager->headerSpeed[threadId])
								< (remLen/otherSpeed)))
				{
					data_buffer_switch_socket(threadId, thisSpeed,
							otherBuff);
					chunkId = bmanager->prevChunkId[otherId];
					bmanager->minNotReadChunkId = MIN(bmanager->minNotReadChunkId, chunkId);
				}/* End of if */
			}
		}/* End of if */
	}/* End of if */
	else
	{
		/* No more chunk mostly this is last chunk */
		uint32 remLen = (DATA_BUFFER_GET_TOTAL_LEN(otherBuff) -
				DATA_BUFFER_GET_OFFSET(otherBuff)) * 8;

		if((ratio >= 2) && ((remLen/thisSpeed) < (remLen/otherSpeed + 5)) && (remLen > (4 * bmanager->minSizeToHandover)))
		{
			TIZEN_LOGD("block_manager_handle_fastcase handover for last chunk Remaining Length %ld This Thread Speed %d Other Speed %d", remLen, thisSpeed, otherSpeed);
			data_buffer_switch_socket(threadId, thisSpeed,otherBuff);
			chunkId = bmanager->prevChunkId[otherId];
			bmanager->minNotReadChunkId = MIN(bmanager->minNotReadChunkId, chunkId);
		}
	}
	return chunkId;
}/* End of handleFastCase() */

int32 block_manager_get_min_not_read_jump_case(int32 chunkId, BlockManager *bmanager)
{
	int32 i = 0;
	int32 ret = 0;

	for (i = chunkId; i < bmanager->noOfChunks; i++)
	{
		ret = DATA_BUFFER_GET_STATE(bmanager->commBuff + i);
		if (ret ==  STATE_NOT_READ || ret == STATE_BLOCKED)
		{
			return i;
		}/* End of if */
	}/* End of for */

	TIZEN_D_LOGD("JUMP Case Equal to Number of CHUNKS\n");
	i = block_manager_get_lastmin_notread_chunkId(bmanager);
	TIZEN_D_LOGD("JUMP Case CHUNK ID got %d",i);
	return i;
}/* End of getMinNotReadJumpCase */

int32 block_manager_handle_slow_case(uint32 ratio,uint32 otherId,BlockManager *bmanager)
{
	int32 chunkId = block_manager_getmin_notread_chunkId(bmanager);

	if (-1 != chunkId)
	{
		if (ratio > 2 && chunkId > bmanager->prevChunkId[otherId])
		{
			bmanager->minNotReadChunkId = MIN(bmanager->minNotReadChunkId, chunkId);
			if (ratio > MAX_JUMP)
			{
				ratio = MAX_JUMP;
			}
			chunkId = bmanager->prevChunkId[otherId] + ratio;
			if (chunkId >= bmanager->noOfChunks)
			{
				TIZEN_D_LOGD("NO chunks left hence starting from last");
				chunkId = block_manager_get_lastmin_notread_chunkId(bmanager);
				TIZEN_D_LOGD("chunk ID from last %d",chunkId);
			}
			else
			{
				chunkId = block_manager_get_min_not_read_jump_case(chunkId, bmanager);
			}
		}
	}/* End of if */
	TIZEN_LOGD("Slow socket got chunk %d",chunkId);
	return chunkId;
}/* End of if */

int32 block_manager_get_lastmin_notread_chunkId(BlockManager *bmanager)
{
	int32 ret = 0;
	int32 chunkid = -1;
	uint32 i = 0;

	for (i = (bmanager->noOfChunks-1); i >= bmanager->minNotReadChunkId; i--)
	{
		ret = DATA_BUFFER_GET_STATE(bmanager->commBuff + i);
		if (ret ==  STATE_NOT_READ || ret == STATE_BLOCKED)
		{
			chunkid = i;
			break;
		}
	}
	return chunkid;
}/* End of getLastMinNotReadChunk() */

int32 block_manager_getmin_notread_chunkId(BlockManager *bmanager)
{
	int32 i = 0;
	int32 ret = 0;

	for (i= bmanager->minNotReadChunkId;i < bmanager->noOfChunks;i++)
	{
		ret = DATA_BUFFER_GET_STATE(bmanager->commBuff + i) ;
		if ((ret ==  STATE_NOT_READ) || (ret == STATE_BLOCKED))
		{
			bmanager->minNotReadChunkId = i+1;
			return i;
		}
	}
	return -1;
}

void block_manager_getmin_notread_chunk(int32 chunkId, int64 *chunkInfo, int32 threadId,
																		int32 socketId, BlockManager *bmanager)
{
	uint64 range1 = (chunkId * bmanager->chunkSize) + bmanager->rspOffset + bmanager->strtOffset;
	uint64 range2 = 0;

	if((chunkId == (bmanager->noOfChunks - 1)) && (bmanager->lastChunkSize != 0))
	{
		range2 = range1 + bmanager->lastChunkSize - 1;
	}/* End of if */
	else
	{
		range2 = ((chunkId + 1 ) * bmanager->chunkSize) + bmanager->strtOffset + bmanager->rspOffset - 1;
	}
	chunkInfo[1] = MIN(range2, ((bmanager->comRspLen + bmanager->strtOffset)-1));

	if (DATA_BUFFER_GET_STATE(bmanager->commBuff +chunkId) == STATE_BLOCKED)
	{
		chunkInfo[0] = range1 + DATA_BUFFER_GET_OFFSET(bmanager->commBuff + chunkId);
		data_buffer_reinit_chunk(threadId, socketId, bmanager->commBuff + chunkId);
	}
	else
	{
		chunkInfo[0] = range1;
		data_buffer_init_chunk(threadId,(chunkInfo[1]-chunkInfo[0] + 1),
				socketId, bmanager->commBuff + chunkId, chunkInfo);
	}
	TIZEN_D_LOGD("block_manager_getmin_notread_chunk CHUNK LENGTH %llu",
			chunkInfo[1] - chunkInfo[0] + 1);
	chunkInfo[2] = chunkId;
}

void block_manager_io_exception(int32 threadId, int32 chunkId,BlockManager *bmanager)
{
	bmanager->prevChunkId[threadId] = -1;
	bmanager->minNotReadChunkId = MIN(bmanager->minNotReadChunkId, chunkId);
}

uint32 block_manager_checkOtherThread(int32 threadId, int32 chunkId,BlockManager *bmanager, uint32 temp_check)
{
	uint32 state = 0;
	uint32 retval = 0;
	uint32 otherId = 0;
	DataBuffer *otherBuff = NULL;
	int8 *default_iname = DEFAULT_INTERFACE;
	if((temp_check == 1) && (bmanager->threadState[otherId] == STATE_THREAD_RUNNING) && (getTempLevel(bmanager->SBData)))
	{
		pthread_mutex_lock(&bmanager->mutex);
		otherId = GET_OTHER_THREAD_ID(threadId);
		if(bmanager->threadState[threadId] == STATE_THREAD_STOPPED)
		{
			retval = 0;
		}
		else if(bmanager->threadState[otherId] == STATE_THREAD_RUNNING)
		{
			int32 thread = threadId;
			if (0 == strncasecmp(default_iname, LTE, strlen(LTE)))
			{
				thread = (thread + 1) % 2;
			}
			if(thread)
			{
				TIZEN_LOGD("Temp More Stopping Current thread as LTE");
				bmanager->threadState[threadId] = STATE_THREAD_STOPPED;
				retval = 1;
			}
			else
			{
				TIZEN_LOGD("Thread %d is stopped due to temp condition and WiFi",otherId);
				bmanager->threadState[otherId] = STATE_THREAD_STOPPED;
				otherBuff = bmanager->commBuff + bmanager->prevChunkId[otherId];
				data_buffer_switch_socket(threadId,bmanager->speed[threadId],otherBuff);
				bmanager->minNotReadChunkId = MIN(bmanager->minNotReadChunkId, bmanager->prevChunkId[otherId]);
				retval = 0;
			}
		}
		pthread_mutex_unlock(&bmanager->mutex);
	}
	if((0 == retval) && (bmanager->threadState[threadId] == STATE_THREAD_RUNNING))
	{
		state = DATA_BUFFER_GET_STATE(bmanager->commBuff + *(bmanager->currentChunkId));

		if(STATE_BLOCKED == state)
		{
			TIZEN_LOGD("Reading chunk %d is blocked\n",*(bmanager->currentChunkId));
			return 1;
		}
	}
	return retval;
}

int32 block_manager_chunk_present(BlockManager *bmanager)
{
	uint32 i = 0;
	uint32 state = 0;

	for (i = bmanager->minNotReadChunkId;i < bmanager->noOfChunks;i++)
	{
		state = DATA_BUFFER_GET_STATE(bmanager->commBuff + i);
		if ((state ==  STATE_NOT_READ) || (state == STATE_BLOCKED))
		{
			return B_TRUE;
		}
	}
	return B_FALSE;
}

int32 block_manager_checkAllBufferStatus(BlockManager *bmanager, int32 threadId)
{
	uint32 i = 0;
	uint32 state = 0;

	for(i=*(bmanager->currentChunkId);i<bmanager->noOfChunks;i++)
	{
		state = DATA_BUFFER_GET_STATE(bmanager->commBuff+i);
		if((state == STATE_FULL_READ) || (state == STATE_CLEARED))
		{
			continue;
		}
		else if(state == STATE_BLOCKED)
		{
			return THREAD_CONTINUE;
		}
		else
		{
			return block_manager_checkSpeed(bmanager,threadId);
		}
	}
	return THREAD_EXIT;
}

uint32 block_manager_checkSpeed(BlockManager *bmanager, int32 threadId)
{
	uint32 retval = 0;
	uint32 thisSpeed = 0;
	uint32 otherSpeed = 0;
	uint32 otherId = 0;
	DataBuffer *otherBuff = NULL;

	thisSpeed = bmanager->speed[threadId];
	otherId = GET_OTHER_THREAD_ID(threadId);
	otherSpeed = bmanager->speed[otherId];
	otherBuff = bmanager->commBuff + bmanager->prevChunkId[otherId];

	if(otherSpeed != 0)
	{
		uint32 remLen = DATA_BUFFER_GET_TOTAL_LEN(otherBuff) - DATA_BUFFER_GET_OFFSET(otherBuff);
		TIZEN_D_LOGD("Block_manager Check Speed Remaining Length %ld This Thread Speed %d Other Speed %d\n", remLen, thisSpeed, otherSpeed );
		if((thisSpeed > otherSpeed) && ((thisSpeed/otherSpeed) >= 2) &&  (remLen > (4 * bmanager->minSizeToHandover)))
		{
			if(((remLen/thisSpeed) < ((remLen/otherSpeed) + 5)))
			{
				retval = 2;
			}
		}
	}
	else
	{
		TIZEN_LOGD("Thread %d is faster than other thread\n",threadId);
		retval = 2;
	}
	return retval;
}

int32 block_manager_check_buffer_status(BlockManager *bmanager)
{
	uint32 i = 0;
	uint32 state = 0;
	uint32 count = 0;

	for(i=*(bmanager->currentChunkId);i<bmanager->noOfChunks;i++)
	{
		state = DATA_BUFFER_GET_STATE(bmanager->commBuff+i); // need to check

		if(state == STATE_FULL_READ)
		{
			count++;
		}
		else if (state == STATE_CLEARED)
		{
			continue;
		}
		else
		{
			break;
		}
	}
	if(count >= 2)
	{
		return 1;
	}
	return 0;
}

void block_manager_exit(BlockManager *bmanager)
{
	TIZEN_LOGD("block_manager_exit\n");
	pthread_mutex_destroy(&bmanager->mutex);
}
