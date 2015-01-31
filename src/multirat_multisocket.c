#include "multirat_libapi.h"
#include "multirat_multisocket.h"
#include "multirat_block_manager.h"
#include "multirat_data_buffer.h"
#include "multirat_range_request_thread.h"
#include "multirat_process.h"
#include "multirat_watch_dog_thread.h"
#include "multirat_watchthread.h"
void multisocket_init(MultiSockInput *mSockInput, SmartBondingData *SBData)
{
	MultiSocket *mSocket = NULL;
	DataBuffer *commbuffer = NULL;
	BlockManager *bmanager = NULL;

	mSocket = malloc(sizeof(MultiSocket));
	if (mSocket == NULL)
		return;

	memset(mSocket, 0, sizeof(MultiSocket));

	mSocket->rspOffset = mSockInput->rspOffset;
	mSocket->noOfChunks = mSockInput->noOfChunks;
	mSocket->strtOffset =  SBData->req.rangeStart;
	mSocket->compRspLen = SBData->resp.cLen ;

	mSocket->appReadLen = 0;
	mSocket->compRspRcvdFlag = 1;
	mSocket->currentChunkId = 0;
	mSocket->conn = mSockInput->conn;

	commbuffer = (DataBuffer *)malloc(mSocket->noOfChunks *	sizeof(DataBuffer));
	if(commbuffer == NULL)
	{
		TIZEN_LOGD("Error !!! commbuffer allocation failure");
		free(mSocket);
		return ;
	}
	memset(commbuffer, 0, mSocket->noOfChunks * sizeof(DataBuffer));

	mSocket->commBuffer = commbuffer;
	SBData->msocket = mSocket;

	data_buffer_init(commbuffer, mSocket->noOfChunks, SBData->cthread->threadId);

	/* Initialize and Sending Block data to Block Manager */
	bmanager = (BlockManager *)malloc(sizeof(BlockManager));
	if(bmanager == NULL)
	{
		TIZEN_LOGD("Error !!! blockMgr allocation failure");
		free(commbuffer);
		free(mSocket);
		return ;
	}
	memset(bmanager, 0, sizeof(BlockManager));
	mSocket->blockMgr = bmanager;

	block_manager_init(mSocket, bmanager,mSockInput);
	mSocket->SBData =  SBData;
	bmanager->SBData = SBData;

}/* End of MultiSocket() */

uint32 multisocket_start(SmartBondingData *SBData)
{
	uint32 i = 0;
	uint32 multiThreadStarted[MAX_INTERFACES] = {0};
	MultiSocket *msocket = SBData->msocket;

	TIZEN_D_LOGD("multisocket_start");

	for (i = 0; i < MAX_INTERFACES; i++ )
	{
		msocket->reqThread[i] = (RangeRequestThread *)malloc(sizeof (RangeRequestThread));
		if(msocket->reqThread[i] == NULL)
		{
			TIZEN_LOGD("Error !!! msocket->reqThread[%d] allocation failure\n", i);
			return 0;
		}
		memset(msocket->reqThread[i], 0, sizeof (RangeRequestThread));
		msocket->reqThread[i]->threadId = i;
		range_request_thread_init(msocket->reqThread[i], SBData);
		multiThreadStarted[i] = range_request_thread_start(msocket->reqThread[i]);
	}
	return (multiThreadStarted[0] && multiThreadStarted[1]);
}/* End of start() */

int32 multisocket_get_firstrange_status(MultiSocket *msocket)
{
	int32 retval = FIRST_RSP_STATUS_PENDING;

	if (RANGE_REQUEST_THREAD_GET_FIRST_RANGE_STATUS(msocket->reqThread[0]) == FIRST_RSP_STATUS_FAILED ||
			RANGE_REQUEST_THREAD_GET_FIRST_RANGE_STATUS(msocket->reqThread[1]) == FIRST_RSP_STATUS_FAILED)
		retval = FIRST_RSP_STATUS_FAILED;

	else if (RANGE_REQUEST_THREAD_GET_FIRST_RANGE_STATUS(msocket->reqThread[0]) == FIRST_RSP_STATUS_PENDING ||
			RANGE_REQUEST_THREAD_GET_FIRST_RANGE_STATUS(msocket->reqThread[1]) == FIRST_RSP_STATUS_PENDING)
		retval = FIRST_RSP_STATUS_PENDING;

	else if (RANGE_REQUEST_THREAD_GET_FIRST_RANGE_STATUS(msocket->reqThread[0]) == FIRST_RSP_STATUS_SUCCESS &&
			RANGE_REQUEST_THREAD_GET_FIRST_RANGE_STATUS(msocket->reqThread[1]) == FIRST_RSP_STATUS_SUCCESS)
		retval = FIRST_RSP_STATUS_SUCCESS;

	return retval;
}/* End of getFirstRangeStatus() */

int32 multisocket_read(int8 *appBuff, uint32 maxAppLen, SmartBondingData *SBData)
{
	uint32 tempLen = 0;
	uint32 toBeRead = 0;
	DataBuffer *currChunk = NULL;
	MultiSocket *msocket = SBData->msocket;

	TIZEN_D_LOGD("multisocket_read current chunk %d\n", msocket->currentChunkId);
	if(msocket->currentChunkId >= msocket->noOfChunks)
	{
		return -1;
	}

	currChunk = msocket->commBuffer + msocket->currentChunkId;
	while (tempLen != maxAppLen)
	{
		if (DATA_BUFFER_GET_TOTAL_LEN(currChunk) == 0)
		{
			/* Block not yet assigned to thread */
			if(currChunk->isContinueChunk == 1)
			{
				if(tempLen > 0)
				{
					break;
				}
				SBData->interface_index = (currChunk->threadId + 1) % 2;
				TIZEN_LOGD("End of multisocket as continue Chunk is present total lenght 0");
				return -2;
			}
			return 0;
		}

		if (DATA_BUFFER_GET_TOTAL_LEN(currChunk) ==
				DATA_BUFFER_GET_READ_RES_LEN(currChunk))
		{
			data_buffer_freeBuffer(currChunk);
			msocket->currentChunkId++;
			if (msocket->currentChunkId >= msocket->noOfChunks)
			{
				msocket->compRspRcvdFlag = 0;
				break;
			}
			currChunk = msocket->commBuffer + msocket->currentChunkId;
			TIZEN_LOGD("started reading block = %d", msocket->currentChunkId);
		}

		if (DATA_BUFFER_GET_RES_BYTES(currChunk)== 0)
		{
			if(currChunk->isContinueChunk == 1)
			{
				if(tempLen > 0)
				{
					break;
				}
				SBData->interface_index = (currChunk->threadId + 1) % 2;
				TIZEN_LOGD("End of multisocket as continue Chunk is present");
				return -2;
			}
			if(DATA_BUFFER_GET_TOTAL_LEN(currChunk) ==
					DATA_BUFFER_GET_READ_RES_LEN(currChunk))
			{
				/* This is for Continued chunk */
				continue;
			}
			break;
		}/* End of if */

		toBeRead = MIN((maxAppLen - tempLen), DATA_BUFFER_GET_RES_BYTES(currChunk));
		data_buffer_read_portion(appBuff + tempLen, toBeRead, currChunk);
		tempLen = tempLen + toBeRead;
	}/* End of while */

	msocket->appReadLen = msocket->appReadLen + tempLen;
	TIZEN_D_LOGD("multisocket_read Application read length %d calculated  %d total lenght %d,tempLen %d\n", msocket->appReadLen,
			(msocket->appReadLen + msocket->rspOffset), msocket->compRspLen,tempLen);
	if((msocket->appReadLen + msocket->rspOffset) == msocket->compRspLen)
	{
		/* Complete response read by application */
		TIZEN_LOGD ("Complete response read by application\n");;
		msocket->compRspRcvdFlag = 0;
	}
	return tempLen;

}/* End of read() */

int32 multisocket_read_sync(int8 *appBuff, uint32 maxAppLen, SmartBondingData *SBData)
{
	uint32 tempLen = 0;
	uint32 toBeRead = 0;
	uint32 rspPresent = 0;
	uint64 startTime = 0;
	DataBuffer *currChunk = NULL;
	MultiSocket *msocket = SBData->msocket;

	TIZEN_D_LOGD("multisocket_read current chunk %d\n", msocket->currentChunkId);

	if(msocket->currentChunkId >= msocket->noOfChunks)
	{
		return -1;
	}

	currChunk = msocket->commBuffer + msocket->currentChunkId;
	while (tempLen != maxAppLen)
	{
		if (DATA_BUFFER_GET_TOTAL_LEN(currChunk) == 0)
		{
			if(currChunk->isContinueChunk == 1)
			{
				if(tempLen > 0)
				{
					break;
				}
				SBData->interface_index = (currChunk->threadId + 1) % 2;
				TIZEN_LOGD("End of multisocket as continue Chunk is present total lenght 0");
				return -2;
			}
			/* Block not yet assigned to thread */
			usleep(1000);
			continue;
		}

		if (DATA_BUFFER_GET_TOTAL_LEN(currChunk) ==
				DATA_BUFFER_GET_READ_RES_LEN(currChunk))
		{
			data_buffer_freeBuffer(currChunk);
			msocket->currentChunkId++;
			if (msocket->currentChunkId >= msocket->noOfChunks)
			{
				msocket->compRspRcvdFlag = 0;
				if(tempLen > 0)
					break;
			}
			currChunk = msocket->commBuffer + msocket->currentChunkId;
			TIZEN_LOGD("started reading block = %d", msocket->currentChunkId);
		}

		startTime = get_time_in_sec();
		rspPresent = 0;
		while (DATA_BUFFER_GET_RES_BYTES(currChunk) == 0)
		{
			if(currChunk->isContinueChunk == 1)
			{
				if(tempLen > 0)
				{
					rspPresent = 1;
					break;
				}
				SBData->interface_index = (currChunk->threadId + 1) % 2;
				TIZEN_LOGD("End of multisocket as continue Chunk is present");
				return -2;
			}

			if (DATA_BUFFER_GET_TOTAL_LEN(currChunk) ==
					DATA_BUFFER_GET_READ_RES_LEN(currChunk))
			{
				/* This is for Continued chunk */
				rspPresent = 2;
				break;
			}
			else if(tempLen > 0)
			{
				rspPresent = 1;
				break;
			}
			else if (((get_time_in_sec() - startTime) > SBData->timeout)|| (SBData->cancel == 1))
			{
				TIZEN_LOGD("No Interface available Exiting multiSocket or Cancel Session" );
				rspPresent = 1;
				break;
			}
			usleep(5000);
		}

		if(2 == rspPresent)
		{
			continue;
		}
		if(1 == rspPresent)
		{
			break;
		}

		toBeRead = MIN((maxAppLen -tempLen), (DATA_BUFFER_GET_RES_BYTES(currChunk)));
		data_buffer_read_portion(appBuff + tempLen, toBeRead, currChunk);
		tempLen = tempLen + toBeRead;
	}/* End of while */

	msocket->appReadLen = msocket->appReadLen + tempLen;
	TIZEN_D_LOGD("multisocket_read Application read length %d calculated  %d total lenght %d\n",
			msocket->appReadLen,(msocket->appReadLen + msocket->rspOffset), msocket->compRspLen);
	if((msocket->appReadLen + msocket->rspOffset) == msocket->compRspLen)
	{
		/* Complete response read by application */
		TIZEN_LOGD ("Complete response read by application\n");;
		msocket->compRspRcvdFlag = 0;
	}
	return tempLen;
}/* End of read() */

void multisocket_exit(MultiSocket *msocket)
{
	uint32 i = 0;
	TIZEN_LOGD("multisocket_exit %p", msocket);
	msocket->compRspRcvdFlag = 0;

	for (i = 0; i < MAX_INTERFACES; i++)
	{
		TIZEN_LOGD("multisocket_exit reqThread[%d] %p", i, msocket->reqThread[i]);
		if (NULL != msocket->reqThread[i])
		{
			range_request_thread_exit (msocket->reqThread[i]);
			msocket->reqThread[i] = NULL;
		}
	}

	TIZEN_LOGD("multisocket_exit blockMgr %p", msocket->blockMgr);
	if(NULL != msocket->blockMgr)
	{
		block_manager_exit(msocket->blockMgr);
		free(msocket->blockMgr);
		TIZEN_LOGD("Block Manager Freed");
	}
	msocket->blockMgr = NULL;

	for (i = 0; i < msocket->noOfChunks; i++)
	{
		TIZEN_LOGD("multisocket_exit commBuffer[%d] %p", i, msocket->commBuffer + i);
		if (NULL != msocket->commBuffer + i)
		{
			data_buffer_exit(msocket->commBuffer + i);
		}
	}

	TIZEN_LOGD("multisocket_exit commBuffer %p", msocket->commBuffer);
	if(msocket->commBuffer != NULL)
	{
		free(msocket->commBuffer);
	}
	msocket->commBuffer = NULL;
	free(msocket);
	msocket = NULL;
	TIZEN_LOGD("multisocket_exit finished\n");
}/* End of ~MultiSocket() */

uint32 is_multirat_read(SmartBondingData *SBData)
{
	/* Read First range request */
	if (NULL != SBData->cthread)
	{
		/*multiSocketThreadStarted*/
		TIZEN_D_LOGD ("about to exit cthread");
		cthread_exit(SBData->cthread);
		SBData->cthread = NULL;
	}
	if (SBData->response_body_read >= SBData->totalExpectedBytes)
	{
		if((SBData->sync))
		{
			uint64 start_time = get_time_in_sec();
			while(multisocket_get_firstrange_status(SBData->msocket) == FIRST_RSP_STATUS_PENDING)
			{
				if(((get_time_in_sec() - start_time) > SBData->timeout)||(SBData->cancel == 1))
				{
					TIZEN_LOGD("Cancel Session or timeout in is_multirat_read");
					break;
				}
				usleep(10000); // sleep for 10 ms
			}
		}
		else if(SBData->curl)
		{
			if(multisocket_get_firstrange_status(SBData->msocket) == FIRST_RSP_STATUS_PENDING)
			{
				if(SBData->CurlStartTime == 0)
					SBData->CurlStartTime = get_time_in_sec();

				if((get_time_in_sec() - SBData->CurlStartTime) > SBData->timeout)
				{
					TIZEN_LOGD("Curl Taken More than TImeout For Buffer Preperation");
					return CURL_TIMEOUT_MULTIRAT_READ;
				}

				return CURL_BLOCK_MULTIRAT_READ;
			}
		}
		if(multisocket_get_firstrange_status(SBData->msocket) == FIRST_RSP_STATUS_SUCCESS)
		{
			SBData->mSocketDataBufferReady = B_TRUE;
			close(SBData->socket_fd);
			SBData->socket_fd = 0;
			TIZEN_LOGD("FirstRangeRequest Success Is Multirat Read\n");
		}
		else
		{
			SBData->mSocketDataBufferReady =  B_FALSE;
			SBData->multiSocketThreadStarted = B_FALSE;
			SBData->enableMultiRat = B_FALSE;
			TIZEN_LOGD("FirstRangeRequest FAILED");
			multisocket_exit(SBData->msocket);
			SBData->msocket = NULL;
		}
	}
	return 0;
}

int32 read_from_buffer(SmartBondingData *SBData,int8 *buffer, uint32 size, int32 *my_nread)
{
	if(SBData->sync)
	{
		*my_nread = multisocket_read_sync(buffer, size, SBData);
		if(*my_nread == 0)
			return SB_ERR;
	}
	else
	{
		*my_nread = multisocket_read(buffer,size, SBData);
		if(*my_nread == 0)
		{
			if(SBData->CurlStartTime == 0)
				SBData->CurlStartTime = get_time_in_sec();

			if((get_time_in_sec() - SBData->CurlStartTime) > SBData->timeout)
			{
				TIZEN_LOGD("Timeout on Reading from Buffer in Curl");
				return SB_ERR;
			}
			return SB_WOULD_BLOCK;
		}
	}
	if (*my_nread == -2)
	{
		SBData->multiSocketThreadStarted = B_FALSE;
		SBData->mSocketDataBufferReady = B_FALSE;
		SBData->enableMultiRat = B_FALSE;
		SBData->socket_fd = 0;
		return handleMainSocExp (SBData,buffer, size, my_nread);
	}

	if(0 != SBData->curl)
		SBData->CurlStartTime = 0;
	return SB_OK;
}

