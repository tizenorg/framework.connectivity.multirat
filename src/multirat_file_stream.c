#include "multirat_libapi.h"
#include "multirat_file_stream.h"
#include "multirat_file_manager.h"
#include "multirat_file_buffer.h"
#include "multirat_range_request_thread.h"
#include "multirat_file_thread.h"
#include "multirat_process.h"
#include "multirat_watch_dog_thread.h"
#include "multirat_watchthread.h"

void file_stream_init(SmartBondingData *SBData)
{
	fileStream *fStream = malloc(sizeof(fileStream));
	fileManager *fileMgr = NULL;

	if(fStream == NULL)
	{
		TIZEN_LOGD("Error malloc fileStream failed");
		return;
	}

	memset(fStream, 0, sizeof(fileStream));

	SBData->fStream = fStream;
	fStream->SBData = SBData;

	fStream->mainSockExpBytes = &(SBData->expectedbytes);
	fStream->totalLen = (SBData->resp.cLen);
	fStream->mainSockRead = &(SBData->response_body_read);
	fStream->strtOffset = SBData->req.rangeStart;

	fileMgr = (fileManager *)malloc(sizeof(fileManager));
	if(fileMgr == NULL)
	{
		TIZEN_LOGD("fileManager Allocation Error");
		return;
	}
	memset(fileMgr, 0, sizeof(fileManager));

	fStream->fileMgr = fileMgr;
	file_manager_init(fStream, fileMgr);
	fileMgr->SBData = SBData;
	fileMgr->interface[MAIN_THREAD] = SBData->interface_index;
	fileMgr->interface[FILE_THREAD] = (SBData->interface_index + 1) % 2;

	fStream->fThread = NULL;
	fStream->compRspRcvdFlag = 1;
}

uint32 file_stream_start(SmartBondingData *SBData)
{
	TIZEN_D_LOGD("File Stream _start");
	fileStream *fStream = SBData->fStream;
	fileThread *fThread = malloc(sizeof (fileThread));
	if(fThread == NULL)
		return 0;
	memset(fThread, 0, sizeof (fileThread));
	fStream->fThread = fThread;
	file_thread_init(fThread, SBData, fStream);
	return file_thread_start(fThread);
}

int32 file_stream_read_from_socket(int32 socket, int8 *buff, uint64 toBeRead, int32 *tempLen, SmartBondingData *SBData, uint32 index)
{
	SBData->sStat.prev_read = MAIN_THREAD ;

	if((index == 1) && (socket == -1))
	{
		SBData->node_exception = SOCKET_NODE_FORCE_EXCEPTION;
		TIZEN_LOGD("Socket is Negative, Go for Main Socket Exception");
		SBData->fStreamFileBufferReady =  B_FALSE;
		SBData->fileThreadStarted = B_FALSE;
		SBData->enableMultiRat = B_FALSE;
		return SB_ERR;
	}
	*tempLen = recv(socket, buff, toBeRead, 0);
	if(*tempLen > 0)
	{
		return SB_OK;
	}
	else
	{
		if((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			if(SBData->curl)
				return SB_WOULD_BLOCK;
			else if(SBData->sync)
			{
				int retval = 0;
				retval = read_conn_poll(socket, SBData);
				if(retval <= 0)
				{
					TIZEN_LOGD("Error !!! Main socket time out");
					return SB_ERR;
				}
				else
				{
					*tempLen = recv(socket, buff, toBeRead, 0);
					if(*tempLen <= 0)
					{
						TIZEN_LOGD("Error !!! Main socket error in recv [%s] ",strerror (errno));
						return SB_ERR;
					}
					return SB_OK;
				}
			}
			else
				return SB_ERR;
		}
		else
		{
			if((index == 0))
			{
				TIZEN_LOGD("Normal Socket Exception");
				SBData->node_exception = SOCKET_NORMAL_EXCEPTION;
				return SB_ERR;
			}
			SBData->node_exception = SOCKET_NODE_NORMAL_EXCEPTION;
			TIZEN_LOGD("Reading from socket node failed [%s] erro No [%d]", strerror(errno), errno);
			TIZEN_LOGD("Go for Main Socket Exception");
			SBData->fStreamFileBufferReady =  B_FALSE;
			SBData->fileThreadStarted = B_FALSE;
			SBData->enableMultiRat = B_FALSE;
			return SB_ERR;
		}
	}
}

int32 file_stream_read(int8 *buff, int32 maxAppLen, SmartBondingData *SBData, int32 *my_nread)
{
	int32 retval = SB_ERR;
	uint64 toBeRead = 0;
	int32 tempLen = -1;
	fileBuffer *fbuff = NULL;

	fileManager *fMgr = SBData->fStream->fileMgr;
	fileBuffer *fileBuff = SBData->fStream->fileBuff;
	if(fileBuff != NULL)
	{
		fbuff = file_manager_getReadingNode(fMgr);
		if(NULL == fbuff)
		{
			return SB_ERR;
		}
		tempLen = 0;
		while(tempLen <= maxAppLen)
		{
			TIZEN_D_LOGD("Reading File Buffer ... [%x] total length  ... [%llu] read length ... [%llu]", fbuff, file_buffer_getTotalLen(fbuff), file_buffer_getReadRspLen(fbuff));
			if(file_buffer_getTotalLen(fbuff) == file_buffer_getReadRspLen(fbuff))
			{
				TIZEN_D_LOGD("completed reading from node [%p] len [%llu]", fbuff, file_buffer_getTotalLen(fbuff));
				if(file_buffer_getNodeType(fbuff) == SOCKET_NODE)
				SBData->status = MAIN_COMPLETE;

				fbuff = file_manager_getReadingNode(fMgr);
				if(NULL == fbuff)
				{
					if(tempLen > 0)
					{
						break;
					}
					return SB_ERR;
				}
			}

			if(tempLen> 0)
			{
				/* already read some bytes */
				break;
			}

			if(file_buffer_getNodeType(fbuff) == SOCKET_NODE)
			{
				TIZEN_D_LOGD("completed reading from socket node [%x] total lenght [%llu]  read length [%llu]", fbuff, file_buffer_getTotalLen(fbuff), file_buffer_getReadRspLen(fbuff));
				toBeRead = MIN(maxAppLen,(file_buffer_getTotalLen(fbuff) - file_buffer_getReadRspLen(fbuff)));
				retval = file_stream_read_from_socket(file_buffer_getSocketId(fbuff), buff, toBeRead, &tempLen, SBData, 1);
				if(tempLen > 0)
				{
					file_buffer_read_from_socket(fbuff, tempLen);
					*my_nread = tempLen;
					TIZEN_D_LOGD("completed reading from socket node [%x] total lenght [%llu]  read length [%llu] ...", fbuff, file_buffer_getTotalLen(fbuff), file_buffer_getReadRspLen(fbuff));
					if(file_buffer_getTotalLen(fbuff) == file_buffer_getReadRspLen(fbuff))
					{
						TIZEN_LOGD("completed reading from Socket node [%x]", fbuff);
						SBData->status = MAIN_COMPLETE;
					}
					return SB_OK;
				}
				else
				{
					if(retval == SB_ERR)
						TIZEN_LOGD("SBData[%p] Sending Error", SBData);
					return retval;
				}
			}
			TIZEN_D_LOGD("Reading File Buffer [%x] total length [%llu] read length [%llu]", fbuff, file_buffer_getTotalLen(fbuff), file_buffer_getReadRspLen(fbuff));
			if(file_buffer_noOfRspBytes(fbuff)== 0)
			{
				if(fbuff->state == NODE_STATE_BLOCKED)
				{
					TIZEN_LOGD("Looks like File Node is Blocked");
					if(!file_manager_file_node_block_handle(SBData))
						return SB_ERR;
				}
				return SB_WOULD_BLOCK;
			}
			toBeRead = MIN((maxAppLen-tempLen),file_buffer_noOfRspBytes(fbuff));

			file_buffer_read_from_file(fbuff, buff+tempLen, &toBeRead);
			tempLen = tempLen + toBeRead;
			TIZEN_D_LOGD("Completed Reading File Buffer [%x] total length [%llu] read length [%llu] ... ", fbuff, file_buffer_getTotalLen(fbuff), file_buffer_getReadRspLen(fbuff));
		}
	}
	else
	{
		TIZEN_LOGD("File buffer not created failed");
		return SB_ERR;
	}
	*my_nread = tempLen;
	return SB_OK;
}

void is_file_stream_read(SmartBondingData *SBData)
{
	fileThread *fThread = SBData->fStream->fThread;
	if (SBData->response_body_read >= SBData->expectedbytes)
	{
		TIZEN_LOGD("Expected Bytes more");
		if(fThread->firstRngStatus == FIRST_RSP_STATUS_SUCCESS)
		{
			TIZEN_LOGD("Read Expected Bytes from Main thread");
			SBData->status = MAIN_COMPLETE;
			SBData->fStreamFileBufferReady = B_TRUE;
			CLOSE_SOCKET(SBData->socket_fd);
			SBData->socket_fd = -1;
			TIZEN_LOGD("FirstRangeRequest Success is_multirat_read");
		}
		else
		{
			SBData->fStreamFileBufferReady =  B_FALSE;
			SBData->fileThreadStarted = B_FALSE;
			SBData->enableMultiRat = B_FALSE;
			TIZEN_LOGD("FirstRangeRequest FAILED");
			file_stream_exit(SBData->fStream);
			SBData->fStream =  NULL;
		}
	}
}

void submit_ratio_history(SmartBondingData *SBData)
{
	FILE *fp = fopen("/opt/usr/media/Ratiostat", "w");
	if(fp == NULL)
	{
		TIZEN_LOGD("Opening File /opt/usr/media/Ratiostat Failed");
		return ;
	}
	fprintf(fp,"%u %u",SBData->speed[1],SBData->speed[0]);
	TIZEN_LOGD("Ratiostat Write Success spd[1] [%u] spd[0] [%u]", SBData->speed[1],SBData->speed[0]);
	fclose(fp);
}

void file_stream_exit(fileStream *fStream)
{
	fileBuffer *fileBuff =  NULL;
	fileBuffer *tempBuff =  NULL;
	TIZEN_LOGD("file stream exit [%p]", fStream);
	fStream->compRspRcvdFlag = 0;
	submit_ratio_history(fStream->SBData);

	if(fStream->SBData->cthread != NULL)
	{
		cthread_exit(fStream->SBData->cthread);
		fStream->SBData->cthread =  NULL;
	}

	file_thread_exit(fStream->fThread);
	fStream->fThread = NULL;

	TIZEN_LOGD("file stream exit file Mgr [%p]", fStream->fileMgr);
	if(NULL != fStream->fileMgr)
	{
		file_manager_exit(fStream->fileMgr);
		free(fStream->fileMgr);
		TIZEN_LOGD("File Manager Freed");
	}
	fStream->fileMgr = NULL;

	fileBuff = fStream->fileBuff ;

	while(fileBuff != NULL)
	{
		tempBuff = fileBuff;
		fileBuff = tempBuff->next;
		file_buffer_exit(tempBuff);
	}
	fileBuff = NULL;
	free(fStream);
	fStream = NULL;

	TIZEN_LOGD("File Stream _exit finished");
}

void PollThread_poll_buffer(SmartBondingData *SBData)
{
	fileManager *fMgr = SBData->fStream->fileMgr;
	fileBuffer *fileBuff = SBData->fStream->fileBuff;
	fileBuffer *fbuff =  NULL;
	uint64 startTime = 0;

	if(fileBuff != NULL)
	{
		fbuff = file_manager_getReadingNode(fMgr);
		if(NULL == fbuff)
		{
			return;
		}
		if(file_buffer_getTotalLen(fbuff) == file_buffer_getReadRspLen(fbuff))
		{
			return;
		}
		if(file_buffer_getNodeType(fbuff) == SOCKET_NODE)
		{
			TIZEN_D_LOGD("Socket Node ... [%x]", fbuff);
			if(fbuff->socketId == -1)
			{
				TIZEN_LOGD("SBData[%p] Socket Node Socket -1", SBData);
				return;
			}
			PollThread_poll(fbuff->socketId, SBData, 10);
			return;
		}
		else
		{
			startTime = get_time_in_sec();
			while(SBData->PollThrd->threadStatus != THREAD_FINISH)
			{
				fbuff = file_manager_getReadingNode(fMgr);
				TIZEN_D_LOGD("SBData[%p] File Node ... [%x]", SBData, fbuff);
				if(NULL == fbuff)
				{
					return;
				}
				if(file_buffer_getTotalLen(fbuff) == file_buffer_getReadRspLen(fbuff))
				{
					TIZEN_LOGD("Node Completed");
					return;
				}
				if(file_buffer_getNodeType(fbuff) != FILE_NODE)
				{
					return;
				}
				if(file_buffer_noOfRspBytes(fbuff)== 0)
				{
					if(fbuff->fThread_read != 0)
					{
						TIZEN_LOGD("Making File Thread Exit");
						SBData->status = MAIN_COMPLETE;
					}
					if(((fbuff->state == NODE_STATE_BLOCKED) && ((get_time_in_sec() - startTime) >= 2)))
					{
						TIZEN_LOGD("SBData[%p] Node State is BLOCK ...", SBData);
						return;
					}
					else
					{
							TIZEN_D_LOGD("SBData[%p] Node State BLOCK sleep", SBData);
					}
					usleep(10000);
					continue;
				}
				else
				{
					return;
				}
			}
		}
	}
}
