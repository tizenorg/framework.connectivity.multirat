#include "multirat_conf.h"
#include "multirat_process.h"
#include "multirat_libapi.h"
#include "multirat_range_request_thread.h"
#include "multirat_connection.h"
#include "multirat_block_manager.h"
#include "multirat_data_buffer.h"
#include "multirat_decode_http.h"
#include <sys/time.h>


void range_request_thread_init(RangeRequestThread *rrthread, SmartBondingData *SBData)
{
	MultiSocket *mSocket = SBData->msocket;
	int8 *default_iname = DEFAULT_INTERFACE;
	uint32 ifaceidx = rrthread->threadId;

	rrthread->pThreadId = 0;
	rrthread->socketId = 0;
	rrthread->minBlockSize = MIN_BLOCK_SIZE;
	rrthread->maxBlockSize = MAX_BLOCK_SIZE;
	rrthread->speedTimeOut = SPEED_TIMEOUT;
	rrthread->blockForSpeed = BLOCK_SIZE_SPEED;
	rrthread->minDataForSpeed =  MIN_DATA_FOR_SPEED;
	rrthread->compRspLen = mSocket->compRspLen;
	rrthread->contRngLen = SBData->resp.instanceSize;
	rrthread->commBuffer = mSocket->commBuffer;
	rrthread->conn = mSocket->conn;
	rrthread->blockMgr = mSocket->blockMgr;
	rrthread->compRspRcvdFlag = &mSocket->compRspRcvdFlag;
	rrthread->firstRngStatus = FIRST_RSP_STATUS_PENDING;

	if (0 == strncasecmp(default_iname, LTE, strlen(LTE)))
	{
		/*
		* thread  0 should get interface LTE (1)
		* and thread 1 should get interface WIFI(0)
		*/
		ifaceidx = (ifaceidx + 1) % 2;
	}

	rrthread->reqHeaders = SBData->req.request[ifaceidx] ;
	rrthread->headerLen = strlen(SBData->req.request[ifaceidx]);

	#if 0
	if(SBData->req.req_buff_wo_range != NULL)
	{
		rrthread->reqHeaders = SBData->req.req_buff_wo_range;
		rrthread->headerLen = SBData->req.req_wo_len;
	}
	else
	{
		rrthread->reqHeaders = SBData->req.req_buff;
		rrthread->headerLen =  SBData->req.reqLen;
	}
	#endif
	rrthread->SBData = SBData;

}/* End of RangeRequestThread() */

uint32 range_request_thread_start(RangeRequestThread *rrthread)
{
	if(0 != pthread_create(&rrthread->pThreadId, NULL,
	range_request_thread_rngreq_thread_callback, (void *)rrthread))
	{
		TIZEN_LOGD("Error !!! while creating range thread");
		range_request_thread_exit(rrthread);
		rrthread = NULL;
		return B_FALSE;
	}
	TIZEN_LOGD("thread ID %d Rangethread started", rrthread->threadId);
	return B_TRUE;
}

void *range_request_thread_rngreq_thread_callback(void *pArg)
{
	RangeRequestThread *rngReq = ((RangeRequestThread*)pArg);
	range_request_thread_run(rngReq);
	return NULL;
}


int range_request_thread_handleIOExp(RangeRequestThread *rrthread, uint32 *ifCount , int iptype)
{
	/* Check if interface is available */
	if (!connection_is_ifaceup(rrthread->threadId, rrthread->conn->ifaceInfo,iptype))
	{
		if((rrthread->firstRngStatus == FIRST_RSP_STATUS_PENDING) && (*ifCount++ > 2))
		{
			rrthread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
			*(rrthread->compRspRcvdFlag) = 0;
			TIZEN_LOGD("First Response Failed for ThreadId %d\n",rrthread->threadId);
			return THREAD_EXIT;
		}
		uint32 otherId = GET_OTHER_THREAD_ID(rrthread->threadId);
		if((rrthread->blockMgr->threadState[otherId] == STATE_THREAD_STOPPED) &&
				(connection_is_ifaceup(otherId, rrthread->conn->ifaceInfo,iptype)))
		{
			TIZEN_LOGD("Swapping thread as other thread is stopped \n");
			rrthread->blockMgr->threadState[rrthread->threadId] = STATE_THREAD_STOPPED;
			rrthread->threadId = otherId;
			rrthread->blockMgr->threadState[otherId] = STATE_THREAD_RUNNING;
			rrthread->blockMgr->noOfIOExp[otherId] = 0;
		}
		else
		{
			return THREAD_CONTINUE;
		}
	}
	/* IOException case */
	connect_server(rrthread);
	TIZEN_LOGD("thread ID %d rrthread->socketId %d\n",rrthread->threadId,rrthread->socketId);
	if ((0 == rrthread->socketId) || (!(*(rrthread->compRspRcvdFlag))))
	{
		if (rrthread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
		{
			rrthread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
			TIZEN_LOGD("First Response failed\n");;
			/* server doest support Range Request */
			/* Exit all threads */
			*(rrthread->compRspRcvdFlag) = 0;
			TIZEN_LOGD("First Response Failed for ThreadId %d\n",rrthread->threadId);
			return THREAD_EXIT;
		}
		else
		{
			return THREAD_CONTINUE;
		}
	}
	return 0;
}

void range_request_thread_handleSendFailCase(RangeRequestThread *rrthread, int32 chunkId)
{
	TIZEN_LOGD("Thread with %d got Exception during send",rrthread->threadId);

	if (rrthread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
	{
		rrthread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
		TIZEN_LOGD("First Response failed\n");;
		/* server doest support Range Request */
		/* Exit all threads */
		*(rrthread->compRspRcvdFlag) = 0;
	}

	if (rrthread->socketId != 0)
	{
		close(rrthread->socketId);
		rrthread->socketId = 0;
	}
	if ((chunkId != -1) && (DATA_BUFFER_GET_THREAD_ID(rrthread->commBuffer + chunkId) == rrthread->threadId))
	{
		/* IO Exception inform Block manager */
		block_manager_io_exception(rrthread->threadId, chunkId, rrthread->blockMgr);
		DATA_BUFFER_SET_STATE(STATE_BLOCKED, (rrthread->commBuffer + chunkId));
	}
}

void range_request_thread_run(RangeRequestThread *rrthread)
{
	int32 retval = 0;
	int32 chunkId = -1;
	int32 blockOffset = 0;
	int32 headerRcvd = B_FALSE;
	int32 IOException = B_TRUE;
	uint32 reqLen = 0;
	uint32 ifCount = 0;
	uint32 blockLen = 0;
	uint32 rngRspLen = 0;
	uint32 connClose = 0;
	uint32 waitThread = B_FALSE;
	uint32 iface_check_count = 0;
	uint32 minBlockLen = rrthread->minBlockSize;
	uint64 endTime = 0;
	uint64 startTime = 0;
	uint64 currChunkLen = 0;
	uint64 chunkStrTime = 0;
	uint64 temp_startTime = 0;
	int64 chunkInfo[CHUNK_INFO_SIZE] = {0};
	int8 *newRequest = NULL;
	//int8 *chunkBuff = NULL;
	int8 tempBuff[MAX_BLOCK_SIZE] = {0};
	DataBuffer *currChunk =  NULL;

	newRequest = (char*)malloc(rrthread->headerLen + MAX_RANGE_FIELD_LEN);
	if(NULL == newRequest)
	{
		return;
	}/* End of if */
	while (*(rrthread->compRspRcvdFlag))
	{
		/* Check the current state of thread */
		if(rrthread->blockMgr->threadState[rrthread->threadId] == STATE_THREAD_STOPPED)
		{
			TIZEN_LOGD("Thread %d stopped state exiting\n",rrthread->threadId);
			break;
		}

		/* Get the status of commonBuffer (memory availability) */
		if (1 == block_manager_check_buffer_status(rrthread->blockMgr))
		{
			usleep(30000);
			continue;
		}/* End of if */

		if(waitThread == B_TRUE)
		{
			retval =  block_manager_checkAllBufferStatus(rrthread->blockMgr,rrthread->threadId);
			if(THREAD_WAIT == retval)
			{
				/* Other thread is downloading this thread has to wait */
				usleep(1000000);
				continue;
			}
			else if (THREAD_EXIT == retval)
			{
				/* Wait thread should exit as other thread has completed */
				TIZEN_LOGD("Download Complete by other thread Exiting Thread Id %d",rrthread->threadId);
				break;
			}
			else if(THREAD_CONTINUE == retval)
			{
				/* Other thread has chunk is blocked */
				TIZEN_LOGD("waiting thread need to download chunk", rrthread->threadId);
				waitThread = B_FALSE;
			}
		}

		if (IOException == B_TRUE)
		{
			retval = 0;
			if(iface_check_count > rrthread->SBData->timeout)
			{
				rrthread->blockMgr->threadState[rrthread->threadId] = STATE_THREAD_STOPPED;
				TIZEN_LOGD("Stopping Thread %d as Interaface is Down For Long Time");
				break;
			}
			retval = range_request_thread_handleIOExp(rrthread,&ifCount,rrthread->SBData->conn.ip_family);
			if(THREAD_EXIT == retval)
			{
				break;
			}
			else if (THREAD_CONTINUE == retval)
			{
				iface_check_count++;
				sleep(1);
				continue;
			}
			iface_check_count = 0;
			IOException = B_FALSE;
		}
		memset(chunkInfo,0,CHUNK_INFO_SIZE*sizeof(int64));

		/* Block Manager for next block */
		block_manager_get_next_chunk(chunkInfo, rrthread->threadId,
										rrthread->socketId, rrthread->blockMgr);

		currChunkLen = chunkInfo[1] - chunkInfo[0] + 1;
		chunkId = chunkInfo[2];
		TIZEN_LOGD("Chunk Id %d Thread Id %d RANGE START %dRANGE END %d\n",
		chunkId, rrthread->threadId, chunkInfo[0] ,chunkInfo[1]);

		if (chunkId < 0)
		{
			/* This condition is for keep-alive case */
			waitThread = B_TRUE;
			continue;
		}

		currChunk = rrthread->commBuffer + chunkId;
		memset(newRequest,0,(rrthread->headerLen + MAX_RANGE_FIELD_LEN));
		reqLen = range_request_thread_rebuild_req(newRequest, chunkInfo, rrthread);

		startTime = get_time_in_microsec();

		if (-1 == send(rrthread->socketId, newRequest, reqLen, 0))
		{
			range_request_thread_handleSendFailCase(rrthread,chunkId);
			IOException = B_TRUE;
			continue;
		}/* End of if */

		rngRspLen = 0;
		headerRcvd = B_FALSE;
		connClose = 0;
		//chunkBuff = DATA_BUFFER_GET_BUFFER(currChunk);

		while (rngRspLen != currChunkLen)
		{
			blockLen =  MIN(minBlockLen, (currChunkLen-rngRspLen));
			minBlockLen = MIN(rrthread->maxBlockSize, (minBlockLen<<1));
			blockOffset = 0;
			memset(tempBuff,0,MAX_BLOCK_SIZE);
			if (0 == headerRcvd)
			{
				retval = range_request_recv_rng_rsp_headers(rrthread->socketId, blockLen, TIME_OUT_MILLISEC,
				rrthread->contRngLen, currChunkLen, &blockOffset, tempBuff, rrthread->compRspLen, &connClose);
				if (HTTP_RSP_DECODING_SUCCESS != retval)
				{
					if (rrthread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
					{
						TIZEN_LOGD("First Response failed\n");;
						/* server doest support Range Request */
						/* Exit all threads */
						*(rrthread->compRspRcvdFlag) = 0;
						rrthread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
					}/* End of else */
					else
					{
						/* IO Exception */
						IOException = B_TRUE;
						TIZEN_LOGD("Thread %d got Exception during recv headers",rrthread->threadId);
					}
					break;
				}
				else
				{
					endTime = get_time_in_microsec();
					temp_startTime = endTime;
					chunkStrTime = endTime;
					uint64 headSpeed = (endTime-startTime)/1000;

					TIZEN_D_LOGD("Thread %d Header speed %d\n",rrthread->threadId,headSpeed);
					SET_HEAD_SPEED(rrthread->threadId,headSpeed,rrthread->blockMgr);
					headerRcvd = B_TRUE;

					/* Success response received from server */
					if (rrthread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
					{
						rrthread->firstRngStatus = FIRST_RSP_STATUS_SUCCESS;
						TIZEN_LOGD("First Response Success\n");
					}
					if (blockOffset > 0)
					{
						data_buffer_add(blockOffset, rrthread->threadId, tempBuff, currChunk);
						rngRspLen = rngRspLen + blockOffset;
					}/* End of if */
				}/* End of else */
			}/* End of if */
			else
			{
				int32 lenRcvd = 0;
				uint32 currOffset = 0;
				uint32 prevOffset = 0;
				uint32 diffOffset = 0;
				uint32 temp_check = 0;
				uint64 speed = 0;
				uint64 avgTime = 0;
				uint64 currTime = 0;
				uint64 prevTime = 0;
				uint64 diffTime = 0;
				uint64 blockStrtTime = 0;
				uint64 blockEndTime = 0;
				int8 *block = tempBuff;

				prevTime = get_time_in_microsec();
				blockStrtTime = prevTime;
				while (blockOffset != blockLen)
				{
					if (conn_poll(rrthread->socketId, TIME_OUT_MILLISEC) <= 0)
					{
						TIZEN_LOGD("Thread %d pollfd <=0\n",rrthread->threadId);
						break;
					}

					lenRcvd = recv(rrthread->socketId,block + blockOffset,blockLen-blockOffset, 0);
					if ((lenRcvd == -1) || (lenRcvd == 0))
					{
						TIZEN_LOGD("Thread %d pollfd recv faill \n",rrthread->threadId);
						break;
					}
					else if (lenRcvd > 0)
					{
						currOffset = currOffset + lenRcvd;
						blockOffset = blockOffset + lenRcvd;
						currTime = get_time_in_microsec();
						blockEndTime = currTime;
						diffTime = (currTime-prevTime) /1000;
						diffOffset = currOffset-prevOffset;
						if((rngRspLen > rrthread->minDataForSpeed) &&
		  						((diffOffset >= rrthread->blockForSpeed) || (diffTime >= rrthread->speedTimeOut)))
						{
	 						prevTime = currTime;
	 						prevOffset = currOffset;
	 						avgTime = (currTime - chunkStrTime)/1000;
	 						if(avgTime > 0)
	 						{
		  						speed = ((rngRspLen + blockOffset) * 8)/avgTime;
	 						}/* End of if */
	 						SET_SPEED(rrthread->threadId,speed, rrthread->blockMgr);
						}
						if((blockEndTime-blockStrtTime) >= BLOCK_TIME_OUT)
						{
	 						blockLen = blockOffset;
						}
					}
				}
				if (blockOffset != blockLen)
				{
					/* IO Exception */
					TIZEN_LOGD("Thread %d IOException during read\n",rrthread->threadId);
					IOException = B_TRUE;
					break;
				}
				else
				{
					temp_check = 0;
					data_buffer_add(blockOffset, rrthread->threadId, tempBuff, currChunk);
					rngRspLen = rngRspLen + blockOffset;

					TIZEN_D_LOGD("Thread %d completed block of len\n",blockLen);
					/* check the other thread status */
					if((currTime - temp_startTime) > TEMP_TIME_OUT)
					{
						TIZEN_D_LOGD("Go For Temperature Checking");
						temp_startTime = currTime;
						temp_check = 1;
					}
					if(block_manager_checkOtherThread(rrthread->threadId,chunkId,rrthread->blockMgr,temp_check))
					{
						TIZEN_LOGD("Thread %d IOException as other thread is blocked read\n",rrthread->threadId);
						IOException = B_TRUE;
						break;
					}
				}
			}
		}/* End of while */
		if (IOException == B_TRUE)
		{
			if ((chunkId != -1) && (DATA_BUFFER_GET_THREAD_ID(rrthread->commBuffer + chunkId) ==
			rrthread->threadId))
			{
				/* close the current fd */
				if (rrthread->socketId != 0)
				{
					close(rrthread->socketId);
					rrthread->socketId = 0;
				}
				/* IO Exception inform Block manager */
				block_manager_io_exception(rrthread->threadId,chunkId, rrthread->blockMgr);
				DATA_BUFFER_SET_STATE(STATE_BLOCKED, (rrthread->commBuffer + chunkId));
				if(blockOffset != blockLen)
				{
					/* Consider only IO Expection due to socket */
					rrthread->blockMgr->noOfIOExp[rrthread->threadId]++;
				}
			}
			else
			{
				/* Current thread is slow Need to check buffer status */
				if (block_manager_chunk_present(rrthread->blockMgr) <= 0)
				{
					waitThread = B_TRUE;
					TIZEN_LOGD("Slow Thread %d is in wait state \n",rrthread->threadId);
				}
				rrthread->socketId = 0;
			}
		}
		else
		{
			TIZEN_LOGD("Thread %d  Completed chunk %d \n",rrthread->threadId, chunkId);
		}
		if ((IOException == B_FALSE) && (1 == connClose))
		{
			IOException = B_TRUE;
			if (block_manager_chunk_present(rrthread->blockMgr) <= 0)
			{
				waitThread = B_TRUE;
				TIZEN_LOGD("Thread %d is in wait state \n",rrthread->threadId);
			}
			if (rrthread->socketId != 0)
			{
				close(rrthread->socketId);
				rrthread->socketId = 0;
			}
		}/* End of if */
	}/* End of while */

	rrthread->blockMgr->threadState[rrthread->threadId] = STATE_THREAD_STOPPED;

	if (rrthread->socketId != 0)
	{
		close(rrthread->socketId);
		rrthread->socketId = 0;
	}

	if(NULL != newRequest)
	{
		free(newRequest);
		newRequest = NULL;
	}/* End of if */

}/* End of run() */

uint32 range_request_thread_rebuild_req(int8 *newRequest, int64 *chunkInfo,RangeRequestThread *rrthread)
{
	int8 rangeField[50] = {0};
	uint32 rangeLen = 0;

	rangeLen = sprintf(rangeField,"%s%lld%s%lld%s","Range: bytes=", chunkInfo[0], "-",
	chunkInfo[1], "\r\n\r\n");

	memcpy(newRequest, rrthread->reqHeaders, rrthread->headerLen);
	newRequest[rrthread->headerLen] = '\0';


	memcpy(newRequest + (rrthread->headerLen - 2), rangeField, rangeLen);
	newRequest[rangeLen + rrthread->headerLen-2] = '\0';
	TIZEN_LOGD("thread ID %d range_request_thread_rebuild_req new req with range =%s\n",
	rrthread->threadId, newRequest);
	return (rangeLen + rrthread->headerLen -2);
}

void range_request_thread_exit(RangeRequestThread *rrthread)
{
	TIZEN_LOGD("range_request_thread_exit %p", rrthread);

	if (0 != rrthread->socketId)
	{
		close(rrthread->socketId);
		rrthread->socketId = 0;
	}

	if (0 != rrthread->pThreadId)
	{
		pthread_join(rrthread->pThreadId,NULL);
		rrthread->pThreadId = 0;
	}

	free(rrthread);
	rrthread = NULL;
	TIZEN_LOGD("range_request_thread_exit Sucess %p", rrthread);
}

int range_request_recv_rng_rsp_headers(int32 socket_fd, uint32 size, uint32 timeout, uint64 instanceSize,
								uint64 currChunkLen, int32 *bodyLen, int8 *blockSize, uint64 respLen, uint32 *connClose)
{
	int32 len = 0;
	int32 rcvdLen = 0;
	int32 retval = -1;
	uint32 offset = 0;
	uint32 headerLen;
	int8 rspSize[MAX_HEADERS_SIZE + 1] = {0};
	int8 rspPrint[MAX_HEADERS_SIZE] = {0};
	httpResp httprsp;

	memset(rspSize, 0, MAX_HEADERS_SIZE + 1);
	memset(rspPrint, 0, MAX_HEADERS_SIZE);

	while (1)
	{
		if(conn_poll(socket_fd, timeout) <= 0)
		{
			TIZEN_LOGD("Poll Error in recv headers");
			return HTTP_RSP_SOCKET_ERROR;
		}/* End of if */
		uint32 min_size = MIN(size, (MAX_HEADERS_SIZE - offset));
		rcvdLen = recv(socket_fd, rspSize + offset,	min_size, 0);
		TIZEN_D_LOGD("thread ID recvd lenght %d\n", rcvdLen);
		if (rcvdLen > 0)
		{
			rspSize[offset + rcvdLen +1] = '\0';
			len = decode_http_find_str(rspSize, END_OF_HEADERS);
			if (-1 != len)
			{
				headerLen = len+4;
				offset  = offset + rcvdLen;
				*bodyLen = offset - headerLen;

				memcpy(rspPrint, rspSize, headerLen);
				TIZEN_LOGD("Response %s\n", rspPrint);
				/* Decode Response headers */
				memset(&httprsp, 0, sizeof(httpResp));
				decode_http_rsp_init(rspSize, headerLen, &httprsp);

				retval = process_http_rsp(&httprsp);
				if (HTTP_RSP_DECODING_SUCCESS == retval)
				{
					retval = range_request_validate_rsp(instanceSize,
	 							&httprsp, currChunkLen, respLen, connClose);

					if((retval == HTTP_RSP_DECODING_SUCCESS) && (*bodyLen > 0))
					{
						/* Copy initial Response to block */
						memcpy(blockSize,rspSize + headerLen,*bodyLen);
					}
				}
				delete_http_rsp(&httprsp);
				return retval;
			}/* End of if */
			else
			{
				offset  = offset + rcvdLen;
				if (offset == MAX_HEADERS_SIZE)
				{
					/* Rsp header too large */
					retval = HTTP_RSP_DECODING_ERROR;
					break;
				}
			}
		}
		else
		{
			TIZEN_LOGD("recv Error in recv headers");
			retval = HTTP_RSP_SOCKET_ERROR;
			break;
		}
	}
	return retval;
}/* End of recvRngRspHeaders() */

int range_request_validate_rsp(uint64 instanceSize, httpResp *httpRsp,
								uint64 currChunkLen, uint64 respLen, uint32 *connClose)
{
	int32 retval = HTTP_RSP_DECODING_ERROR;
	int8 *rspCode = DECODE_HTTP_RSP_GET_RSP_CODE(httpRsp);
	int8 *contLen =  DECODE_HTTP_RSP_GET_CONT_LEN(httpRsp);
	int8 *conn = DECODE_HTTP_RSP_GET_CONNECTION(httpRsp);

	if(conn != NULL)
	{
		if(0 == strncasecmp(conn,"close",strlen("close")))
		{
			*connClose = 1;
		}/* End of if */
	}

	if ((rspCode != NULL) && (contLen != NULL))
	{
		if ((0 == strncasecmp(rspCode, "200 OK", strlen("200 OK")))
				|| (0 == strncasecmp(rspCode, "206 Partial Content",strlen("206 Partial Content"))))
		{
			uint64 rcvdContLen = atol(contLen);
			TIZEN_LOGD("rcvdContLen %llu Expected %llu",rcvdContLen,currChunkLen);
			if (rcvdContLen == currChunkLen)
			{
				uint64 rcvdContRngLen = decode_http_rsp_get_cont_rnglen(httpRsp->contRange);
				TIZEN_LOGD("rcvdContRngLen %llu contRngLen %llu compRspLen %s",
				rcvdContRngLen, instanceSize, contLen);
				if ((instanceSize != 0) && (instanceSize == rcvdContRngLen))
				{
					retval = HTTP_RSP_DECODING_SUCCESS;
				}
				else if (rcvdContRngLen == respLen)
				{
					retval = HTTP_RSP_DECODING_SUCCESS;
				}
			}
		}
	}
	return retval;
}
