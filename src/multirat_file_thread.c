#include "multirat_conf.h"
#include "multirat_process.h"
#include "multirat_libapi.h"
#include "multirat_range_request_thread.h"
#include "multirat_connection.h"
#include "multirat_file_manager.h"
#include "multirat_file_buffer.h"
#include "multirat_decode_http.h"
#include "multirat_file_thread.h"
#include "multirat_watch_dog_thread.h"

#include <sys/time.h>

void file_thread_init(fileThread *fThread, SmartBondingData *SBData, fileStream *fStream)
{
	TIZEN_LOGD("File Thread Init");
	fThread->pthreadId = 0;
	fThread->compRspRcvdFlag = &(fStream->compRspRcvdFlag);
	fThread->compRspLen = SBData->resp.cLen ;
	fThread->contRngLen = SBData->resp.instanceSize;
	fThread->SBData = SBData;
	fThread->conn = &SBData->conn;
	fThread->socketId = -1;
	fThread->fileMgr = fStream->fileMgr;
	fThread->firstRngStatus = FIRST_RSP_STATUS_PENDING;
}

uint32 file_thread_start(fileThread *fThread)
{
	uint32 multiThreadStarted = B_TRUE;
	if(0 != pthread_create(&fThread->pthreadId, NULL, &FileThreadCallBack, fThread))
	{
		TIZEN_LOGD("File thread failed");
		multiThreadStarted = B_FALSE;
	}
	return multiThreadStarted;
}

void *FileThreadCallBack(void *ptr)
{
	fileThread *fileReq = (fileThread*)ptr;
	file_thread_run(fileReq);
	return NULL;
}

void file_thread_run(fileThread *fThread)
{
	int8 *newRequest = NULL;
	int8 tempBuff[2*MAX_BLOCK_SIZE] = {0};
	int8 rcvBuff[MAX_HEADER_SIZE + 1] = {0};
	int32 headerRcvd = B_FALSE;
	int32 IOException = B_TRUE;
	int32 FIRST_TIME = B_TRUE;
	int64 chunkInfo[CHUNK_INFO_SIZE] ={0};
	uint32 reqLen = 0;
	uint32 minBlockLen = MIN_BLOCK_SIZE;
	uint32 ifCount = 0;
	uint32 connClose = 0;
	uint32 ifaceidx = fThread->interface_index;
	uint64 currChunkLen = 0;
	uint64 rcvdLen = 0;
	uint64 blockOffset = 0;
	uint32 status = 0;
	uint64 blockLen = 0;
	int32 lengthRcvd = 0;
	fileBuffer *fbuffer = NULL;
	fThread->status = FILE_START;
	SmartBondingData *SBData = NULL;
	fileManager *fileMgr = fThread->fileMgr;
	SBData = fThread->SBData;
	TIZEN_LOGD("File Thread Main");

	while(*fThread->compRspRcvdFlag)
	{
		int32 return_val = 0;

		fThread->interface_index =  file_manager_get_file_thread_interface(fileMgr);
		ifaceidx = fThread->interface_index;
		TIZEN_LOGD("Interface Index [%d]", fThread->interface_index );

		if (IOException == B_TRUE)
		{
			int32 retval = 0;

			retval = file_thread_handleIOExp(fThread,&ifCount,SBData->conn.ip_family);

			if(THREAD_EXIT == retval)
			{
				break;
			}
			else if (THREAD_CONTINUE == retval)
			{
				sleep(1);
				continue;
			}
		}

		fbuffer = file_manager_getNextChunkForFileThread(chunkInfo, SBData);

		if(NULL == fbuffer)
		{
			break;
		}

		fThread->status = FILE_START;
		fThread->interface_index =  file_manager_get_file_thread_interface(fileMgr);
	
		if(fbuffer->fThread_read != FILE_THREAD_SOCK_READ)
		{
			if(ifaceidx != fThread->interface_index)
			{
				int32 retval = 0;

				retval = file_thread_handleIOExp(fThread,&ifCount,SBData->conn.ip_family);

				if(THREAD_EXIT == retval)
				{
					break;
				}
				else if (THREAD_CONTINUE == retval)
				{
					sleep(1);
					continue;
				}
			}
			ifaceidx = fThread->interface_index ;

			if((FIRST_TIME != B_TRUE))
			{
				return_val = file_thread_connet_server_interface(fThread);
				if(THREAD_EXIT == return_val)
				{
					break;
				}
				else if (THREAD_CONTINUE == return_val)
				{
					sleep(1);
					continue;
				}

				fThread->req = SBData->req.request[ifaceidx] ;
				fThread->headerLen = strlen(SBData->req.request[ifaceidx]);

				if(newRequest != NULL)
					free(newRequest);

				newRequest = (int8 *)malloc(fThread->headerLen + MAX_RANGE_FIELD_LEN);
				if(NULL == newRequest)
				{
					return;
				}

				memset(newRequest,0,(fThread->headerLen + MAX_RANGE_FIELD_LEN));
				reqLen = file_thread_rebuildReq(newRequest, chunkInfo, fThread);

				SECURE_DB_INFO("In file thread New Request [%s]",newRequest) ;

				if(-1 == send(fThread->socketId,newRequest,reqLen,0))
				{
					TIZEN_LOGD("Sending of HTTP Req from File Thread Failed");
					break;
				}
				headerRcvd = B_FALSE;
			}
			else
			{
				int32 result = -1;
				TIZEN_LOGD("First Time File Thread Connection");
				result = file_thread_FirstConnection(fThread->SBData, fThread, chunkInfo, rcvBuff, &lengthRcvd);
				return_val = file_thread_connect_server_interface_first(result, fThread);
				if(THREAD_EXIT == return_val)
				{
					break;
				}
				else if (THREAD_CONTINUE == return_val)
				{
					sleep(1);
					continue;
				}
				headerRcvd = B_FALSE;
			}
			fbuffer->socketId = fThread->socketId ;
		}
		else
		{
			fThread->socketId = fbuffer->socketId;
			headerRcvd = B_TRUE;
		}
		currChunkLen = chunkInfo[1] - chunkInfo[0] + 1;
		TIZEN_LOGD("File Thread Interface Index [%d]",fThread->interface_index);
		TIZEN_LOGD("currChunkLen [%llu]",currChunkLen);
		IOException = B_FALSE;
		minBlockLen = MIN_BLOCK_SIZE;
		rcvdLen = 0;

		while(rcvdLen < currChunkLen && *fThread->compRspRcvdFlag)
		{
			blockOffset = 0;
			status = 0;
			blockLen = MIN(minBlockLen, currChunkLen - rcvdLen);
			minBlockLen = MIN((2*MAX_BLOCK_SIZE),(minBlockLen << 2));
			memset(tempBuff,0,2*MAX_BLOCK_SIZE);

			/*If  Main thread Read stops for more than 2 sec , file thread stops reading */
			if(SBData->read_state_check == MAIN_SOCK_READ_INACTIVE)
			{
				usleep(10000);
				continue;
			}

			TIZEN_LOGD("File Thread Total Len [%llu] received [%llu] Block Len [%llu]",file_buffer_getTotalLen(fbuffer), rcvdLen, blockLen);
			status = file_manager_check_main_thread_status(fileMgr);
			if((status == MAIN_IO_EXCEPTION) && (SBData->file_status != NO_REDIVISION))
			{
				TIZEN_LOGD("IO Exception of Main Socket");
				fThread->status = FILE_IO_EXCEPTION;
				fbuffer->state = NODE_STATE_BLOCKED;
				IOException = B_TRUE;
				break;
			}
			else if((status == MAIN_COMPLETE)&& (SBData->file_status != NO_REDIVISION))
			{
				TIZEN_LOGD("Main Thread is Completed");
				fThread->status = MAIN_COMPLETE;
				fbuffer->state = NODE_STATE_BLOCKED;
				IOException = B_TRUE;
				break;
			}
			if(B_FALSE == headerRcvd)
			{
				int32 retval = HTTP_RSP_DECODING_ERROR;
				if(FIRST_TIME == B_TRUE)
				{
					retval = file_thread_range_request_recv_rng_rsp_headers_first_req(&blockOffset, tempBuff, currChunkLen, &connClose, fThread, rcvBuff, lengthRcvd);
					FIRST_TIME = B_FALSE;
				}
				else
					retval = file_thread_range_request_recv_rng_rsp_headers(&blockOffset, tempBuff, currChunkLen, &connClose, fThread);
				if(HTTP_RSP_DECODING_SUCCESS != retval)
				{
					if((fThread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
							&& (retval == HTTP_RSP_DECODING_ERROR))
					{
						TIZEN_LOGD("First Response failed");
						*fThread->compRspRcvdFlag = 0;
						fThread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
					}
					else
					{
						IOException = B_TRUE;
						TIZEN_LOGD("File Thread got Exception during recv headers");
					}
					break;
				}
				else
				{
					headerRcvd = B_TRUE;
					if(fThread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
					{
						fThread->firstRngStatus = FIRST_RSP_STATUS_SUCCESS;
						TIZEN_LOGD("First Response Success");
					}
					if(blockOffset > 0)
					{
						uint64 temp_history = 0;
						uint64 temp_data = 0;
						speedStat *sStat = &(SBData->sStat);
						file_buffer_add(fbuffer, tempBuff, blockOffset, chunkInfo, rcvdLen, SBData);
						if(SBData->bRafMode)
						{
							sprintf(SBData->FileData,"%lld-%llu",chunkInfo[0],file_buffer_getOffset(fbuffer));
						}
						rcvdLen = rcvdLen + blockOffset;

						temp_data = sStat->recv_length[fThread->interface_index];
						sStat->recv_length[fThread->interface_index] = sStat->recv_length[fThread->interface_index] + blockOffset;
						if(sStat->start_recv_time[fThread->interface_index] == 0)
							sStat->start_recv_time[fThread->interface_index] = get_time_in_microsec();
						sStat->prev_recv_time[fThread->interface_index] = get_time_in_microsec();
						temp_history = (sStat->prev_recv_time[fThread->interface_index] - sStat->start_recv_time[fThread->interface_index])/1000000;
						if((sStat->timeArray[fThread->interface_index] < (MAX_HISTORY)) && (temp_history < MAX_HISTORY) && (temp_history > sStat->timeArray[fThread->interface_index]))
						{
							int i = 0;
							sStat->dataArray[fThread->interface_index][temp_history] = sStat->recv_length[fThread->interface_index];
							for( i = sStat->timeArray[fThread->interface_index] + 1 ;  i < temp_history; i++)
							{
								sStat->dataArray[fThread->interface_index][i] = temp_data;
							}
							sStat->timeArray[fThread->interface_index] = temp_history;
							TIZEN_LOGD("Data History Time [%llu] Data [%llu]", temp_history, sStat->dataArray[fThread->interface_index][temp_history]);
							TIZEN_LOGD("temp_hist [%llu] tdata [%llu] Data [%llu]", temp_history, temp_data, sStat->dataArray[fThread->interface_index][temp_history]);
						}
						TIZEN_LOGD("File Thread Total Len [%llu] received [%llu] Block Len [%llu]",file_buffer_getTotalLen(fbuffer), rcvdLen, blockLen);
					}
				}
			}
			else
			{
				int32 lenRcvd = 0;
				while(blockOffset != blockLen)
				{
					if (file_thread_conn_poll(fThread->socketId, SBData) <= 0)
					{
						TIZEN_LOGD("File Thread Fail Polling");
						IOException = B_TRUE;
						break;
					}
					//sleep(1);
					lenRcvd = recv(fThread->socketId, tempBuff+blockOffset, blockLen-blockOffset,0);
					if((lenRcvd == -1) || (lenRcvd == 0))
					{
						break;
					}
					else if(lenRcvd > 0)
					{
						blockOffset = blockOffset + lenRcvd;
						uint64 temp_history = 0;
						uint64 temp_data = 0;
						speedStat *sStat = &(SBData->sStat);
						temp_data = sStat->recv_length[fThread->interface_index];

						sStat->recv_length[fThread->interface_index] = sStat->recv_length[fThread->interface_index] + lenRcvd;

						if(sStat->start_recv_time[fThread->interface_index] == 0)
							sStat->start_recv_time[fThread->interface_index] = get_time_in_microsec();

						sStat->prev_recv_time[fThread->interface_index] = get_time_in_microsec();

						temp_history = (sStat->prev_recv_time[fThread->interface_index] - sStat->start_recv_time[fThread->interface_index])/1000000;
						if((sStat->timeArray[fThread->interface_index] < (MAX_HISTORY)) && (temp_history < MAX_HISTORY) && (temp_history > sStat->timeArray[fThread->interface_index]))
						{
							int i = 0;
							sStat->dataArray[fThread->interface_index][temp_history] = sStat->recv_length[fThread->interface_index];
							for( i = sStat->timeArray[fThread->interface_index] + 1 ;  i < temp_history; i++)
							{
								sStat->dataArray[fThread->interface_index][i] = temp_data;
							}
							sStat->timeArray[fThread->interface_index] = temp_history;
							TIZEN_LOGD("idx [%d] Data History Time [%llu] Data [%llu]", fThread->interface_index, temp_history, sStat->dataArray[fThread->interface_index][temp_history]);
						}
					}
				}
				if(blockOffset != blockLen)
				{
					/* IO Exception */
					TIZEN_LOGD("File Thread  IOException during read");
					IOException = B_TRUE;
					break;
				}
				else
				{
					TIZEN_LOGD("File Buffer Write [%x]", fbuffer);
					//file_buffer_add(fbuffer, tempBuff, blockOffset);
					file_buffer_add(fbuffer, tempBuff, blockOffset,chunkInfo,rcvdLen,SBData);

					if(SBData->bRafMode)
					{
						sprintf(SBData->FileData,"%lld-%llu",chunkInfo[0],file_buffer_getOffset(fbuffer));
					}
					rcvdLen = rcvdLen + blockOffset;
					TIZEN_D_LOGD("File Thread Total Len [%llu] received [%llu] Block Len [%llu]", file_buffer_getTotalLen(fbuffer), rcvdLen, blockLen);
				}
			}
		}
		if((IOException == B_TRUE) && (file_buffer_getTotalLen(fbuffer) != rcvdLen))
		{
			fbuffer->state = NODE_STATE_BLOCKED;
			IOException = B_TRUE;
			if(SBData->file_status == NO_REDIVISION)
			{
				TIZEN_LOGD("Close Socket ID As Exception and No Redivision");
				fThread->status = FILE_IO_EXCEPTION;
				CLOSE_SOCKET(fbuffer->socketId);
				fbuffer->socketId = 0;
				fThread->socketId = 0;
			}
			else if((fThread->SBData->status == MAIN_COMPLETE))
			{
				TIZEN_LOGD("Dont Close Socket ID As Main Complete");
				if(blockOffset > 0)
				{
					TIZEN_LOGD("File Buffer Write [%x] Data Length [%llu]", fbuffer, blockOffset);
					file_buffer_add(fbuffer, tempBuff, blockOffset,chunkInfo,rcvdLen,SBData);
					if(SBData->bRafMode)
					{
						sprintf(SBData->FileData,"%lld-%llu",chunkInfo[0],file_buffer_getOffset(fbuffer));
					}
				}
				fThread->status = MAIN_COMPLETE;
			}
			else
			{
				TIZEN_LOGD("Close Socket ID As Exception and Main is not Complete");
				fThread->status = FILE_IO_EXCEPTION;
				CLOSE_SOCKET(fbuffer->socketId);
				fbuffer->socketId = -1;
				fThread->socketId = -1;
			}

			TIZEN_LOGD("File Thread Interupted Download FILE NODE [%x] Total length [%llu] Received [%llu]", fbuffer, file_buffer_getTotalLen(fbuffer), file_buffer_getOffset(fbuffer));
		}
		else
		{
			fThread->status = FILE_COMPLETE; // Means here it is complete
			TIZEN_LOGD("File Thread Finished Downloading FILE NODE [%x] Total length [%llu] Received [%llu]", fbuffer, file_buffer_getTotalLen(fbuffer), file_buffer_getOffset(fbuffer));

			if(fThread->SBData->file_status == NO_REDIVISION)
				*fThread->compRspRcvdFlag = 0;

			if(NULL == fbuffer->next)
			{
				TIZEN_LOGD("Close Socket ID as No Available Buffer");
				CLOSE_SOCKET(fbuffer->socketId);
				fbuffer->socketId = -1;
				fThread->socketId = -1;
				fThread->status = FILE_COMPLETE;
				IOException = B_TRUE;
			}
			if(NULL != fbuffer->next && fThread->socketId != file_buffer_getSocketId(fbuffer->next))
			{
				TIZEN_LOGD("Close Socket ID as Next Avalaible Buffer Socket is Not Same");
				CLOSE_SOCKET(fbuffer->socketId);
				fbuffer->socketId = -1;
				fThread->socketId = -1;
				fThread->status = FILE_COMPLETE;
				IOException = B_TRUE;
			}
		}
	}
	TIZEN_LOGD("Exiting FILE THREAD");
	if(NULL != newRequest)
	{
		free(newRequest);
		newRequest = NULL;
	}
	TIZEN_LOGD("Exiting FILE THREAD ...");
}


int file_thread_handleIOExp(fileThread *fThread, uint32 *ifCount,int iptype)
{
	/* Check if interface is available */
	if (!connection_is_ifaceup(fThread->interface_index, fThread->conn->ifaceInfo,iptype))
	{
		if((fThread->firstRngStatus == FIRST_RSP_STATUS_PENDING) && (*ifCount++ > 2))
		{
			fThread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
			*(fThread->compRspRcvdFlag) = 0;
			TIZEN_LOGD("First Response Failed for File ThreadId");
			return THREAD_EXIT;
		}
		else
		{
			return THREAD_CONTINUE;
		}
	}
	/* IOException case */
	return 0;
}


int file_thread_connect_server_interface_first(int32 result, fileThread *fThread)
{
	fThread->socketId = result;
	TIZEN_LOGD("File Thread socketId [%d]", fThread->socketId);
    if ((-1 == fThread->socketId) || (!(*(fThread->compRspRcvdFlag))))
    {
        if (fThread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
        {
            fThread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
            TIZEN_LOGD("First Response failed");;
            /* server doest support Range Request */
            /* Exit all threads */
            *(fThread->compRspRcvdFlag) = 0;
            TIZEN_LOGD("First Response Failed for File ThreadId");
            return THREAD_EXIT;
        }
        else
        {
            if(fThread->SBData->file_status == NO_REDIVISION)
            {
                fThread->status = FILE_IO_EXCEPTION;
            }
            else if(fThread->SBData->status == MAIN_COMPLETE)
            {
                fThread->status = MAIN_COMPLETE;
            }
            else
            {
                fThread->status = FILE_IO_EXCEPTION;
            }
            return THREAD_CONTINUE;
        }
    }
    return 0;
}

int file_thread_connet_server_interface(fileThread *fThread)
{
	file_thread_connect_server(fThread);
	TIZEN_LOGD("File Thread socketId [%d]", fThread->socketId);

	if ((0 > fThread->socketId) || (!(*(fThread->compRspRcvdFlag))))
	{
		if (fThread->firstRngStatus == FIRST_RSP_STATUS_PENDING)
		{
			fThread->firstRngStatus = FIRST_RSP_STATUS_FAILED;
			TIZEN_LOGD("First Response failed");;
			/* server doest support Range Request */
			/* Exit all threads */
			*(fThread->compRspRcvdFlag) = 0;
			TIZEN_LOGD("First Response Failed for File ThreadId");
			return THREAD_EXIT;
		}
		else
		{
			if(fThread->SBData->file_status == NO_REDIVISION)
			{
				fThread->status = FILE_IO_EXCEPTION;
			}
			else if(fThread->SBData->status == MAIN_COMPLETE)
			{
				fThread->status = MAIN_COMPLETE;
			}
			else
			{
				fThread->status = FILE_IO_EXCEPTION;
			}
			return THREAD_CONTINUE;
		}
	}
	return 0;
}



int32 file_thread_range_request_recv_rng_rsp_headers_first_req(uint64 *bodyLen, char *blockSize, uint64 currChunkLen, uint32 *connClose, fileThread *fThread, int8 *rcvBuff, int32 lengthRcvd)
{
	uint32 offset = lengthRcvd;
	int32 retval = -1;
	int32 len = 0;
	int8 rspPrint[MAX_HEADERS_SIZE] = {0};
	httpResp httpRsp ;
	uint64 instanceSize =  fThread->contRngLen;
	uint64 respLen = fThread->compRspLen;
	len = decode_http_find_str(rcvBuff, END_OF_HEADERS);
	uint32 headerLen = (len+4);
	*bodyLen = (uint64)(offset - headerLen);
	memcpy(rspPrint, rcvBuff, headerLen);
	SECURE_DB_INFO("Response [%s]", rspPrint);
	TIZEN_LOGD("Total Data Received [%d]", lengthRcvd);
	memset(&httpRsp, 0, sizeof(httpResp));
	decode_http_rsp_init(rcvBuff, headerLen, &httpRsp);
	retval = process_http_rsp(&httpRsp);
	if(HTTP_RSP_DECODING_SUCCESS == retval)
	{
		TIZEN_LOGD("File Thread Response Decode Success");
		retval = range_request_validate_rsp(instanceSize, &httpRsp, currChunkLen, respLen, connClose);
		if((retval == HTTP_RSP_DECODING_SUCCESS) && (*bodyLen > 0))
		{
			memcpy(blockSize,rcvBuff+headerLen,*bodyLen);
		}
	}
	delete_http_rsp(&httpRsp);
	TIZEN_LOGD("File Thread Response Decode Success ...");
	return retval;
}

int32 file_thread_range_request_recv_rng_rsp_headers(uint64 *bodyLen, char *blockSize, uint64 currChunkLen, uint32 *connClose, fileThread *fThread)
{
	int32 rcvdLen = 0;
	uint32 offset = 0;
	int32 retval = -1;
	int32 len = 0;
	int8 rspSize[MAX_HEADERS_SIZE] = {0};
	int8 rspPrint[MAX_HEADERS_SIZE] = {0};
	httpResp httpRsp ;
	uint64 instanceSize =  fThread->contRngLen;
	uint64 respLen = fThread->compRspLen;
	while(1)
	{
		TIZEN_LOGD("Recv Response");
		if (file_thread_conn_poll(fThread->socketId, fThread->SBData) <= 0)
		{
			TIZEN_LOGD("File Thread Fail Polling");
			return HTTP_RSP_SOCKET_ERROR;
		}
		TIZEN_LOGD("Recved Response");
		rcvdLen = recv(fThread->socketId,rspSize+offset,MAX_HEADERS_SIZE-offset,0);
		if(rcvdLen > 0)
		{
			rspSize[offset + rcvdLen +1] = '\0';
			len = decode_http_find_str(rspSize,END_OF_HEADERS);
			if(-1 != len)
			{
				uint32 headerLen = len+4;
				offset  = offset + rcvdLen;
				*bodyLen = offset-headerLen;
				memcpy(rspPrint, rspSize, headerLen);
				SECURE_DB_INFO("Response [%s]", rspPrint);
				memset(&httpRsp, 0, sizeof(httpResp));
				decode_http_rsp_init(rspSize, headerLen, &httpRsp);
				retval = process_http_rsp(&httpRsp);
				if(HTTP_RSP_DECODING_SUCCESS == retval)
				{
					TIZEN_LOGD("File Thread Response Decode Success");
					retval = range_request_validate_rsp(instanceSize,
							&httpRsp, currChunkLen, respLen, connClose);
					if((retval == HTTP_RSP_DECODING_SUCCESS) && (*bodyLen > 0))
					{
						memcpy(blockSize,rspSize+headerLen,*bodyLen);
					}
				}
				delete_http_rsp(&httpRsp);
				TIZEN_LOGD("File Thread Response Decode Success ...");
				return retval;
			}
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
			retval = HTTP_RSP_SOCKET_ERROR;
			break;
		}
	}
	return retval;
}

int32 file_thread_rebuildReq(char *newRequest, int64 *chunkInfo, fileThread *fThread)
{
	int32 rangeLen = 0;
	int8 rangeField[MAX_RANGE_FIELD_LEN] = {0};
	rangeLen = sprintf(rangeField,"%s%llu%s%llu%s","Range: bytes=",chunkInfo[0],"-",chunkInfo[1],"\r\n\r\n");
	memcpy(newRequest, fThread->req, fThread->headerLen - 2);
	memcpy(newRequest + fThread->headerLen -2, rangeField, rangeLen);
	return (rangeLen+fThread->headerLen);
}

void file_thread_exit(fileThread *fThread)
{
	TIZEN_LOGD("File_Thread_Exit [%p]", fThread);

	if (0 < fThread->socketId)
	{
		shutdown(fThread->socketId, 1);
	}

	if (0 != fThread->pthreadId)
	{
		pthread_join(fThread->pthreadId,NULL);
		TIZEN_LOGD("File Thread Closed");
		fThread->pthreadId = 0;
	}
	if (0 < fThread->socketId)
	{
		CLOSE_SOCKET(fThread->socketId);
		fThread->socketId = -1;
	}
	free(fThread);
	fThread = NULL;
	TIZEN_LOGD("File Thread Exit Sucess [%p]", fThread);
}

