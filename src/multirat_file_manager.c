#include "multirat_file_buffer.h"
#include "multirat_file_manager.h"
#include "multirat_process.h"
#include "multirat_conf.h"
#include "multirat_process.h"
#define MAX_TIMEFORALL_BY0 5
#define MAX_TIMEFORALL_BY1 4

#define SAME_INTERFACE_NO_DIVIDE 0
#define CHANGE_INTERFACE_NO_DIVIDE 2
#define DIVIDE 1

void file_manager_init(fileStream *fStream, fileManager *fileMgr)
{
	fileMgr->ExpectedBytes = (fStream->mainSockExpBytes);
	fileMgr->rspRead = fStream->mainSockRead;
	fileMgr->totalLen = fStream->totalLen;
	fileMgr->strtOffset = fStream->strtOffset;
	fileMgr->fbuffer = &fStream->fileBuff;
	fileMgr->thread_exception = B_FALSE;
	pthread_mutex_init(&(fileMgr->mutex), NULL);
}

fileBuffer *file_manager_getNextChunkForFileThread(int64 *chunkInfo, SmartBondingData *SBData)
{
	fileManager *fileMgr = SBData->fStream->fileMgr;
	fileStream *fStream = SBData->fStream;
	fileThread *fThread = fStream->fThread;
	fileBuffer *newfileBuf = NULL;

	pthread_mutex_lock(&(fileMgr->mutex));
	TIZEN_LOGD("Get Next Chunk For File Thread");

	// This is First Chunk Alloted for the File Thread
	if(*fileMgr->fbuffer == NULL)
	{
		TIZEN_LOGD("First Chunk");
		chunkInfo[0] = *fileMgr->ExpectedBytes + fileMgr->strtOffset;
		chunkInfo[1] =  fileMgr->totalLen - 1 + fileMgr->strtOffset;

		newfileBuf = (fileBuffer *)malloc(sizeof(fileBuffer));
		if(newfileBuf == NULL)
		{
			TIZEN_LOGD("File Buffer Allocation Failed");
			pthread_mutex_unlock(&(fileMgr->mutex));
			return NULL;
		}
		memset(newfileBuf, 0, sizeof(fileBuffer));
		file_buffer_init_node(newfileBuf, chunkInfo, -1, FILE_NODE, SBData, 0);
		newfileBuf->next = NULL;
		*fileMgr->fbuffer = newfileBuf;

		TIZEN_LOGD("New Node Created [%x] and Total length [%llu] New Node [%x]", newfileBuf, file_buffer_getTotalLen(newfileBuf), fStream->fileBuff);
	}
	// This is For handling the case where File Thread just comes up and starts downloading but main is reading File Buffer ...
	// In that it will continue to use File Buffer:
	// IO Exception of Main Thread And IO exception of File Thread handled Similarly
	if(SBData->status == MAIN_COMPLETE)
	{
		TIZEN_LOGD("Main Complete");
		fThread->status = MAIN_COMPLETE;
	}
	// This is Handling Case When File Thread vitness IO Exception or Main Thread IO Exception
	if(fThread->status == FILE_IO_EXCEPTION)
	{
		TIZEN_LOGD("File Io Exception");
		newfileBuf = file_manager_get_next_chunk_handle_file_io_exception(fileMgr, chunkInfo);
	}

	// This is For Handling Case When Main Thread is Complete
	else if(fThread->status == MAIN_COMPLETE)
	{
		TIZEN_LOGD("Main Thread Completed");
		newfileBuf = file_manager_get_next_chunk_handle_main_complete(fileMgr, chunkInfo);
	}

	// This is For Handling Case When File Thread has Finished
	else if(fThread->status == FILE_COMPLETE)
	{
		TIZEN_LOGD("File Thread Complete");
		newfileBuf = file_manager_get_next_chunk_handle_file_complete(fileMgr, chunkInfo);
	}

	// Finally Setting main thread Status to Start
	SBData->status = MAIN_START;
	pthread_mutex_unlock(&(fileMgr->mutex));
	return newfileBuf;
}


fileBuffer *file_manager_getReadingNode(fileManager *fileMgr)
{
	fileBuffer *tempBuff = *fileMgr->fbuffer;
	uint32 state = 0;

	while(tempBuff != NULL)
	{
		state = file_buffer_getState(tempBuff);
		if(state == NODE_STATE_DOWNLOADING || state == NODE_STATE_BLOCKED || state == NODE_STATE_FULL_READ)
		{
			break;
		}
		tempBuff = tempBuff->next;
	}
	return tempBuff;
}


fileBuffer *file_manager_getDownloadingNode(fileManager *fileMgr)
{
	fileBuffer *tempBuff = *fileMgr->fbuffer;
	uint32 state = 0;

	while(tempBuff != NULL)
	{
		state = file_buffer_getState(tempBuff);
		if(state == NODE_STATE_DOWNLOADING || state == NODE_STATE_BLOCKED)
		{
			break;
		}
		tempBuff = tempBuff->next;
	}
	return tempBuff;
}

fileBuffer *file_manager_getDownloadingFileNode(fileManager *fileMgr)
{
	fileBuffer *tempBuff = *fileMgr->fbuffer;
	uint32 state = 0;
	uint32 type = 0;
	while(tempBuff != NULL)
	{
		state = file_buffer_getState(tempBuff);
		type = file_buffer_getType(tempBuff);
		if((state == NODE_STATE_DOWNLOADING || state == NODE_STATE_BLOCKED) && (type == FILE_NODE))
		{
			break;
		}
		tempBuff = tempBuff->next;
	}
	TIZEN_LOGD("Download File Node [%x]",tempBuff);
	return tempBuff;
}

uint32 file_manager_divideCont(uint64 remCont, int64 *contInfo, fileManager *fileMgr, uint32 nodeType)
{
	double temp2 = 0;
	uint64 temp = 0;
	SmartBondingData *SBData = fileMgr->SBData;
	uint32 other_index = 0;

	uint32 index_main = file_manager_get_main_thread_interface(fileMgr);
	uint32 index_file = file_manager_get_file_thread_interface(fileMgr);

	uint64 interfaceSpeed0 = 0;
	uint64 interfaceSpeed1 = 0;

	if(nodeType == FILE_NODE)
	{
		other_index = index_main;
		interfaceSpeed0 = SBData->speed[index_file];
		interfaceSpeed1 = SBData->speed[index_main];
	}
	else
	{
		other_index = index_file;
		interfaceSpeed1 = SBData->speed[index_file];
		interfaceSpeed0 = SBData->speed[index_main];
	}

	uint64 temp_cal = 0;
	uint64 temp_time0 = 0;
	double ratio = 0;
	uint64 time0= 0;
	uint64 time1= 0;
	if(interfaceSpeed1)
		ratio = MAX(0.1, MIN(10,(float)interfaceSpeed0/(float)interfaceSpeed1));
	else
	{
		TIZEN_LOGD("ratio assigned 10 value as interfaceSpeed1 is 0");
		ratio = 10;
	}

	TIZEN_LOGD("RemainContent [%llu] Interface0 Speed [%llu] Interface1 Speed [%llu] Ratio [%lf]", remCont, interfaceSpeed0, interfaceSpeed1, ratio);
	temp2 = (float)(remCont)/(ratio + 1);
	temp = abs(temp2);
	time0 = (temp2 * 8 )/interfaceSpeed0;
	time1 = (temp2 * 8 )/interfaceSpeed1;

	TIZEN_LOGD("temp [%llu] temp2 [%lf] time0 [%llu] time1 [%llu]", temp, temp2,time0,time1);


	temp_time0 = ((remCont - temp)*8)/interfaceSpeed0;
	TIZEN_LOGD("temp_time0 [%llu]", temp_time0);

	// 2 sec for slow start
	if(time0 < 2)
	{
		TIZEN_LOGD("Time Less Than 2 Sec, same inter. no divide");
		return SAME_INTERFACE_NO_DIVIDE;
	}
	else
	{
		TIZEN_LOGD("Dividing");
		/* Stores the seconds for which we have initial bytes captured for this interface */
		uint64 new_connection_slow_time = MIN(SBData->sStat.timeArray[other_index], MAX_HISTORY-1);
		uint64 bytes_loss1 = 0;
		uint64 bytes_loss0 = 0;

		if(time1 < new_connection_slow_time)
			new_connection_slow_time = time1;

		uint64 bytes_speed = 0; /* Bytes based on speed in specific time */
		uint64 bytes_loss_slow_start = 0; /* Bytes loss as connection was in slow start initially */
		/* Initial new_connection_slow_time seconds we get only below bytes in temp_cal */
		temp_cal = SBData->sStat.dataArray[other_index][new_connection_slow_time];

		/* As per the interfacespeed we should get this many bytes*/
		bytes_speed = new_connection_slow_time * interfaceSpeed1/8;
		if(bytes_speed > temp_cal)
			bytes_loss_slow_start = bytes_speed - temp_cal;

		/* Now we should divide again this more load bytes_loss_slow_start on other_index
		across two interfaces, so divide this in two parts based on speed ration and
		now see  */
		bytes_loss1 = (float)(bytes_loss_slow_start)/(ratio + 1);
		bytes_loss0 = bytes_loss_slow_start - bytes_loss1;
		if(temp > bytes_loss0)
			temp -= bytes_loss0;

		TIZEN_LOGD("new_conn_slow [%llu] loss0 [%llu] loss1 [%llu] bytes_speed [%llu], temp_cal [%llu], bytes_loss_slow_start [%llu] temp [%llu]", new_connection_slow_time, bytes_loss0, bytes_loss1, bytes_speed,temp_cal, bytes_loss_slow_start, temp);

		contInfo[1] = temp;
		contInfo[0] = remCont - temp;
	}
	TIZEN_LOGD("First Part [%lld] Second part [%lld]", contInfo[0], contInfo[1]);
	return DIVIDE;
}

uint32 file_manager_divideRemCont(uint64 remCont, fileManager *fileMgr, uint32 nodeType)
{
	TIZEN_LOGD("Divide remCont [%llu]", remCont);
	SmartBondingData *SBData = fileMgr->SBData;
	uint32 index_main = file_manager_get_main_thread_interface(fileMgr);
	uint32 index_file = file_manager_get_file_thread_interface(fileMgr);
	uint32 other_index = 0;
	uint64 temp_data1 = 0;
	if(SBData->division_count++ > 5)
	{
		TIZEN_LOGD("MAX DIVISION COUNT REACHED...  No more division ");
		return SAME_INTERFACE_NO_DIVIDE;
	}
	TIZEN_LOGD("DIVISION COUNT is [%d]",SBData->division_count);

	if(remCont > (MAX_BLOCK_SIZE* 4))
	{
		double interfaceTime0 = 0;
		double interfaceTime1 = 0;
		uint64 interfaceSpeed0 = 0;
		uint64 interfaceSpeed1 = 0;

		if(nodeType == FILE_NODE)
		{
			other_index = index_main;
			if((SBData->speed[index_file] == 0))
			{
				TIZEN_LOGD("idx main [%d] file [%d] speed file index 0, CHANGE_INTERFACE_NO_DIVIDE", index_main, index_file);
				return CHANGE_INTERFACE_NO_DIVIDE;
			}
			if((SBData->speed[index_main] == 0))
			{
				TIZEN_LOGD("idx main [%d] file [%d] speed main index 0, SAME_INTERFACE_NO_DIVIDE", index_main, index_file);
				return SAME_INTERFACE_NO_DIVIDE;
			}
			interfaceSpeed0 = SBData->speed[index_file];
			interfaceSpeed1 = SBData->speed[index_main];
			interfaceTime0 = (float)(remCont*8)/ (float)interfaceSpeed0;
			interfaceTime1 = (float)(remCont*8)/ (float)interfaceSpeed1;
		}
		else
		{
			other_index = index_file;
			if((SBData->speed[index_main] == 0))
			{
				TIZEN_LOGD("Skt idx main [%d] file [%d] speed main index 0, CHANGE_INTERFACE_NO_DIVIDE", index_main, index_file);
				return CHANGE_INTERFACE_NO_DIVIDE;
			}
			if((SBData->speed[index_file] == 0))
			{
				TIZEN_LOGD("Skt idx main [%d] file [%d] speed file index 0, SAME_INTERFACE_NO_DIVIDE", index_main, index_file);
				return SAME_INTERFACE_NO_DIVIDE;
			}
			interfaceSpeed1 = SBData->speed[index_file];
			interfaceSpeed0 = SBData->speed[index_main];
			interfaceTime1 = (float)(remCont*8)/ (float)interfaceSpeed1;
			interfaceTime0 = (float)(remCont*8)/ (float)interfaceSpeed0;
		}

		TIZEN_LOGD("Interface0 Speed [%llu] Interface1 Speed [%llu]", interfaceSpeed0, interfaceSpeed1);
		TIZEN_LOGD("Interface0 Time [%lf] Interface1 time [%lf]", interfaceTime0, interfaceTime1);
		TIZEN_LOGD("Time Array Other Interface Index [%llu]", SBData->sStat.timeArray[other_index]);
		if(SBData->sStat.timeArray[other_index] < MAX_TIMEFORALL_BY1)
		{

			temp_data1 = SBData->sStat.dataArray[other_index][SBData->sStat.timeArray[other_index]] + (interfaceSpeed1 *
			(MAX_TIMEFORALL_BY1 - SBData->sStat.timeArray[other_index]))/8;
		}
		else
		{
			temp_data1 = SBData->sStat.dataArray[other_index][MAX_TIMEFORALL_BY1];
		}

		TIZEN_LOGD("tmpdata1 Data in 4 secs [%llu]", temp_data1);
		if(interfaceTime0 < MAX_TIMEFORALL_BY0)
		{
			TIZEN_LOGD("The Current interface Time Less Than 5");
			return SAME_INTERFACE_NO_DIVIDE;
		}
		else if((interfaceTime1 < MAX_TIMEFORALL_BY1) && (remCont <= temp_data1))
		{
			TIZEN_LOGD("Other interface Time Less Than 4");
			return CHANGE_INTERFACE_NO_DIVIDE;
		}
		else if(interfaceSpeed1 < 2000)
		{
			TIZEN_LOGD("Speed of other Interface is less");
			return SAME_INTERFACE_NO_DIVIDE;
		}
		else if(interfaceSpeed0 < 2000)
		{
			TIZEN_LOGD("Speed of This Interface is less");
			return CHANGE_INTERFACE_NO_DIVIDE;
		}
		return DIVIDE;
	}
	else
	{
		TIZEN_LOGD("Remaing Content is Less");
		return SAME_INTERFACE_NO_DIVIDE;
	}
}

void file_manager_setSpeed(uint32 index, uint32 speed, SmartBondingData *SBData)
{
	SBData->speed[index] = speed;
}

void file_manager_exit(fileManager *fileMgr)
{
	pthread_mutex_destroy(&(fileMgr->mutex));
}

uint32 file_manager_get_file_thread_interface(fileManager *fileMgr)
{
	return 	fileMgr->interface[FILE_THREAD];
}
uint32 file_manager_get_main_thread_interface(fileManager *fileMgr)
{
	return fileMgr->interface[MAIN_THREAD];
}

uint32 file_manager_check_main_thread_status(fileManager *fileMgr)
{
	return fileMgr->SBData->status;
}

fileBuffer * file_manager_get_next_chunk_handle_file_io_exception(fileManager *fileMgr, int64 *chunkInfo)
{
	fileBuffer *tempBuff = file_manager_getDownloadingFileNode(fileMgr);
	fileBuffer *newfileBuf = NULL;
	if(tempBuff != NULL)
	{
		pthread_mutex_lock(&(tempBuff->mut));
		uint64 socketOffset = file_buffer_getOffset(tempBuff);
		TIZEN_LOGD("Data in File Node is [%llu]", socketOffset);
		newfileBuf = tempBuff;
		chunkInfo[0] = tempBuff->startOffset + socketOffset;
		chunkInfo[1] = tempBuff->endOffset;
		file_buffer_reinit_node(newfileBuf, -1, FILE_NODE);
		pthread_mutex_unlock(&(tempBuff->mut));
	}
	return newfileBuf;
}

fileBuffer * file_manager_get_next_chunk_handle_main_complete(fileManager *fileMgr, int64 *chunkInfo)
{
	fileBuffer *newfileBuf = NULL;
	fileBuffer *tempBuff = file_manager_getDownloadingFileNode(fileMgr);
	uint64 remContent = 0;
	uint32 divide = B_FALSE;
	int64 contInfo[2] = {0};

	if(tempBuff != NULL)
	{
		pthread_mutex_lock(&(tempBuff->mut));
		TIZEN_LOGD("Offset of Downloading File Buffer [%llu]", file_buffer_getOffset(tempBuff));
		uint64 socketOffset = file_buffer_getOffset(tempBuff);

		if(socketOffset == 0)
		{
			TIZEN_LOGD("Data in File Node is Zero Making as Socket Node");
			file_manager_SwitchSocketNoData(tempBuff, fileMgr);
			pthread_mutex_unlock(&(tempBuff->mut));
			return NULL;
		}

		remContent = file_buffer_getTotalLen(tempBuff) - socketOffset;
		TIZEN_LOGD("Remaining Content [%llu] offset [%llu]", remContent, socketOffset);

		divide =  file_manager_divideRemCont(remContent, fileMgr, FILE_NODE);
		//divide = 1;
		if(!divide)
		{
			TIZEN_LOGD("Make This File Node as Socket Node and Continue Downloading");
			TIZEN_LOGD("Data in File Node is Not Zero Creating New Socket Node and Use Same Interface");
			newfileBuf = file_manager_SwitchSocketData(tempBuff, fileMgr, chunkInfo, 0);
		}
		else
		{	//divide = 2;
			if(divide == CHANGE_INTERFACE_NO_DIVIDE)
			{
				TIZEN_LOGD("Data in File Node is Not Zero Creating New Socket Node and Use Diff Interface");
				newfileBuf = file_manager_SwitchSocketData(tempBuff, fileMgr, chunkInfo, 1);
			}
			else
			{
				TIZEN_LOGD("Division According to Speed");
				divide = file_manager_divideCont(remContent, contInfo, fileMgr, FILE_NODE);
				TIZEN_LOGD("Divide [%d]",divide);
				//divide = 1;
				if(!divide)
				{
					TIZEN_LOGD("Data in File is not Zero, Creating new Socket Node and Use Same Interface");
					newfileBuf = file_manager_SwitchSocketData(tempBuff, fileMgr, chunkInfo, 0);
				}
				else
				{
					TIZEN_LOGD("Need to Divide File Node");
					fileBuffer *newfileBuftemp =  NULL;
					TIZEN_LOGD("Data in File is not Zero, Make 3 Nodes");
					file_buffer_setTotalLen(socketOffset, tempBuff);
					TIZEN_LOGD("Set the Total Lenght to offset [%llu]", socketOffset);

					check_set_filebuff_state(tempBuff);

					newfileBuf = (fileBuffer *)malloc(sizeof(fileBuffer));
					memset(newfileBuf, 0, sizeof(fileBuffer));
					chunkInfo[0] = file_buffer_getStrtOffset(tempBuff) + file_buffer_getTotalLen(tempBuff);
					chunkInfo[1] = chunkInfo[0] + contInfo[0] - 1;
					TIZEN_LOGD("Start Offset [%llu] Total length [%llu]", file_buffer_getStrtOffset(tempBuff), file_buffer_getTotalLen(tempBuff));
					TIZEN_LOGD("Chunk 0 [%lld] Chunk 1 [%lld] cont [%lld]", chunkInfo[0], chunkInfo[1], contInfo[0]);
					//TIZEN_LOGD("ichunk 0 %lld ichunk 1 %lld cont %lld", chunkInfo[0], chunkInfo[1], contInfo[0]);
					file_buffer_init_node(newfileBuf, chunkInfo, tempBuff->socketId, SOCKET_NODE, fileMgr->SBData, 0);
					fileMgr->interface[MAIN_THREAD] = (fileMgr->interface[MAIN_THREAD] + 1) % 2;
					fileMgr->interface[FILE_THREAD] = (fileMgr->interface[FILE_THREAD] + 1) % 2;
					fileMgr->SBData->interface_index = fileMgr->interface[MAIN_THREAD];
					newfileBuf->next = tempBuff->next;
					tempBuff->next = newfileBuf;

					TIZEN_LOGD("New Node Created [%x] and Total length [%llu]", newfileBuf, file_buffer_getTotalLen(newfileBuf));
					newfileBuftemp = (fileBuffer *)malloc(sizeof(fileBuffer));
					memset(newfileBuftemp, 0, sizeof(fileBuffer));

					chunkInfo[0] = chunkInfo[1] + 1;
					chunkInfo[1] = tempBuff->endOffset;

					tempBuff->endOffset = file_buffer_getStrtOffset(tempBuff) + file_buffer_getTotalLen(tempBuff) - 1;

					file_buffer_init_node(newfileBuftemp, chunkInfo, -1, FILE_NODE, fileMgr->SBData, 0);
					newfileBuftemp->next = newfileBuf->next;
					newfileBuf->next = newfileBuftemp;
					newfileBuf = newfileBuftemp;
					TIZEN_LOGD("New Node Created [%x] and Total length [%llu]", newfileBuf, file_buffer_getTotalLen(newfileBuf));
				}
			}
		}
		pthread_mutex_unlock(&(tempBuff->mut));
	}
	return newfileBuf;
}

fileBuffer * file_manager_get_next_chunk_handle_file_complete(fileManager *fileMgr, int64 *chunkInfo)
{
	fileBuffer *newfileBuf = NULL;
	uint64 remContent = 0;
	uint32 divide = B_FALSE;
	int64 contInfo[2] = {0};

	if(*fileMgr->rspRead < *fileMgr->ExpectedBytes)
	{
		remContent = *fileMgr->ExpectedBytes - *fileMgr->rspRead;
		TIZEN_LOGD("File Thread Finished File Node ... Checking Dividing Expected Bytes [%llu] Remaing Content [%llu]", *fileMgr->ExpectedBytes, remContent);
		divide =  file_manager_divideRemCont(remContent, fileMgr, SOCKET_NODE);
		if(divide)
		{
			if(divide == CHANGE_INTERFACE_NO_DIVIDE)
			{
				TIZEN_LOGD("No Need to Divide Main Socket Just Change Interface");
				if(fileMgr->SBData->node_exception == 0) // Only if Main Socket is not going for exception Close this
				{
					CLOSE_SOCKET(fileMgr->SBData->socket_fd);
				}
			}
			else
			{
				TIZEN_LOGD("Division According to Speed");
				if(file_manager_divideCont(remContent, contInfo, fileMgr, SOCKET_NODE))
				{
					newfileBuf = (fileBuffer *)malloc(sizeof(fileBuffer));
					if(newfileBuf != NULL)
					{
						memset(newfileBuf, 0, sizeof(fileBuffer));
						chunkInfo[1] = *fileMgr->ExpectedBytes - 1 + fileMgr->strtOffset;
						*fileMgr->ExpectedBytes = *fileMgr->rspRead + contInfo[0];
						chunkInfo[0] = *fileMgr->ExpectedBytes + fileMgr->strtOffset;
						file_buffer_init_node(newfileBuf, chunkInfo, -1, FILE_NODE, fileMgr->SBData, 0);
						/* Attach to head head */
						newfileBuf->next = *fileMgr->fbuffer;
						*fileMgr->fbuffer = newfileBuf;

						TIZEN_LOGD("New Node Created [%x] and Total length [%llu] Reduce Expected Bytes [%llu]", newfileBuf, file_buffer_getTotalLen(newfileBuf), *fileMgr->ExpectedBytes);
					}
				}
			}
		}
	}
	else
	{
		TIZEN_LOGD("File Thread Dividing Socket Node");
		fileBuffer *tempBuff = file_manager_getDownloadingNode(fileMgr);
		if(tempBuff != NULL)
		{
			pthread_mutex_lock(&(tempBuff->mut));
			uint64 socketOffset = file_buffer_getOffset(tempBuff);
			remContent = file_buffer_getTotalLen(tempBuff) - socketOffset;
			TIZEN_LOGD("Rem Con [%llu] offset [%llu]",remContent, socketOffset);
			divide =  file_manager_divideRemCont(remContent, fileMgr, SOCKET_NODE);
			if(divide)
			{
				if(divide == CHANGE_INTERFACE_NO_DIVIDE)
				{
					TIZEN_LOGD("No Need to Divide Socket Node Just Change Interface");

					if(fileMgr->SBData->node_exception == 0) // Only if Main Socket is not going for exception Close this
					{
						CLOSE_SOCKET(tempBuff->socketId);
					}
					//tempBuff->socketId = 0;
				}
				else
				{
					TIZEN_LOGD("Division According to Speed");
					if(file_manager_divideCont(remContent, contInfo, fileMgr, SOCKET_NODE))
					{
						newfileBuf = (fileBuffer *)malloc(sizeof(fileBuffer));
						if(newfileBuf != NULL)
						{
							memset(newfileBuf, 0, sizeof(fileBuffer));
							file_buffer_setTotalLen(socketOffset + contInfo[0], tempBuff);

							check_set_filebuff_state(tempBuff);

							chunkInfo[0] = file_buffer_getStrtOffset(tempBuff) + file_buffer_getTotalLen(tempBuff);
							chunkInfo[1] =  tempBuff->endOffset;

							tempBuff->endOffset = chunkInfo[0] - 1;

							TIZEN_LOGD("End Offset Node [%x] [%llu] Total length [%llu]", tempBuff, tempBuff->endOffset, file_buffer_getTotalLen(tempBuff));
							file_buffer_init_node(newfileBuf, chunkInfo, -1, FILE_NODE, fileMgr->SBData, 0);
							/* Attach new node after current node */
							newfileBuf->next = tempBuff->next;
							tempBuff->next = newfileBuf;
							TIZEN_LOGD("New Node Created [%x] and Total length [%llu]", newfileBuf, file_buffer_getTotalLen(newfileBuf));
						}
					}
				}
			}
			pthread_mutex_unlock(&(tempBuff->mut));
		}
	}
	return newfileBuf;
}

void file_manager_update_socket_node(uint64 offset, SmartBondingData *SBData)
{
	fileBuffer *tempBuff = file_manager_getDownloadingNode(SBData->fStream->fileMgr);
	TIZEN_LOGD("Socket Node [%x] setting offset [%llu] Socket [%d]", tempBuff, offset, SBData->socket_fd);
	tempBuff->offset = tempBuff->offset + offset;
	tempBuff->appReadLen = tempBuff->appReadLen + offset;
	tempBuff->socketId = SBData->socket_fd;
}

void file_manager_SwitchSocketNoData(fileBuffer *tempBuff, fileManager *fileMgr)
{
	if(tempBuff->fThread_read)
	{
		TIZEN_LOGD("Created During File Thread socket Read");
		tempBuff->fThread_read = 0;
		fileMgr->interface[MAIN_THREAD] = (fileMgr->interface[MAIN_THREAD] + 1) % 2;
		fileMgr->interface[FILE_THREAD] = (fileMgr->interface[FILE_THREAD] + 1) % 2;
		fileMgr->SBData->interface_index = fileMgr->interface[MAIN_THREAD];
	}

	CLOSE_SOCKET(tempBuff->socketId);
	tempBuff->socketId = -1;
	file_buffer_reinit_node(tempBuff, -1, SOCKET_NODE);
}

fileBuffer *file_manager_SwitchSocketData(fileBuffer *tempBuff, fileManager *fileMgr, int64 *chunkInfo, int ifacechange)
{
	fileBuffer *newfileBuf = (fileBuffer *)malloc(sizeof(fileBuffer));
	uint32 newfilebuf_null = 0;
	uint64 socketOffset = file_buffer_getOffset(tempBuff);
	if(newfileBuf != NULL)
	{
		memset(newfileBuf, 0, sizeof(fileBuffer));
		file_buffer_setTotalLen(socketOffset, tempBuff);
		check_set_filebuff_state(tempBuff);
		chunkInfo[0] = file_buffer_getStrtOffset(tempBuff) + file_buffer_getTotalLen(tempBuff);
		chunkInfo[1] =  tempBuff->endOffset;
		if(ifacechange == 0)
		{
			TIZEN_LOGD("No Need to Change Interface");
			if((tempBuff->bRafMode) || (tempBuff->fThread_read) || (socketOffset < MIN_FILE_NODE_SIZE))
			{
				file_buffer_init_node(newfileBuf, chunkInfo, tempBuff->socketId, SOCKET_NODE, fileMgr->SBData, 0);
				fileMgr->interface[MAIN_THREAD] = (fileMgr->interface[MAIN_THREAD] + 1) % 2;
				fileMgr->interface[FILE_THREAD] = (fileMgr->interface[FILE_THREAD] + 1) % 2;
				fileMgr->SBData->interface_index = fileMgr->interface[MAIN_THREAD];
				newfilebuf_null = 1;
			}
			else
			{
				TIZEN_LOGD("Raf Mode OFF making File Thread Read From Socket");
				file_buffer_init_node(newfileBuf, chunkInfo, tempBuff->socketId, FILE_NODE, fileMgr->SBData, FILE_THREAD_SOCK_READ);
			}
		}
		else
		{
			TIZEN_LOGD("Change The Interface");
			if((tempBuff->bRafMode) || (tempBuff->fThread_read) || (socketOffset < MIN_FILE_NODE_SIZE))
			{
				file_buffer_init_node(newfileBuf, chunkInfo, -1, SOCKET_NODE, fileMgr->SBData, 0);
 				newfilebuf_null = 1;
			}
			else
			{
				TIZEN_LOGD("Raf Mode OFF Making File Thread Read From Socket");
				file_buffer_init_node(newfileBuf, chunkInfo, -1, FILE_NODE, fileMgr->SBData, FILE_THREAD_SOCK_CREATE);
				fileMgr->interface[MAIN_THREAD] = (fileMgr->interface[MAIN_THREAD] + 1) % 2;
				fileMgr->interface[FILE_THREAD] = (fileMgr->interface[FILE_THREAD] + 1) % 2;
				fileMgr->SBData->interface_index = fileMgr->interface[MAIN_THREAD];
 			}
		}
		/* Attach new node after current node */
		newfileBuf->next = tempBuff->next;
		tempBuff->next = newfileBuf;
		TIZEN_LOGD("New Node Created [%x] and Total length [%llu]", newfileBuf, file_buffer_getTotalLen(newfileBuf));
		if(newfilebuf_null)
		{
			newfileBuf = NULL;
			tempBuff->fThread_read = 0;
		}
	}
	return newfileBuf;
}

uint32 file_manager_file_node_block_handle(SmartBondingData *SBData)
{
	fileManager *fileMgr = SBData->fStream->fileMgr;
	fileBuffer *tempBuff = NULL;
	uint64 socketOffset = 0;
	uint32 retval = B_FALSE;
	pthread_mutex_lock(&(fileMgr->mutex));
	SBData->fStream->fThread->status = FILE_COMPLETE;
	tempBuff = file_manager_getDownloadingNode(fileMgr);
	if(tempBuff == NULL)
	{
		pthread_mutex_unlock(&(fileMgr->mutex));
		return B_TRUE;
	}
	pthread_mutex_lock(&(tempBuff->mut));
	if(tempBuff->state !=  NODE_STATE_BLOCKED)
	{
		retval =  B_TRUE;
	}
	else
	{
		TIZEN_LOGD("File Node in Blocked State");
		socketOffset = file_buffer_getOffset(tempBuff);
		if(socketOffset == 0)
		{
			TIZEN_LOGD("Data in File Node is Zero Making as Socket Node");
			file_manager_SwitchSocketNoData(tempBuff, fileMgr);
			retval = B_TRUE;
		}
		else
		{
			int64 contInfo[2] = {0};
			fileBuffer *newfileBuf = (fileBuffer *)malloc(sizeof(fileBuffer));
			if(newfileBuf != NULL)
			{
				memset(newfileBuf, 0, sizeof(fileBuffer));
				file_buffer_setTotalLen(socketOffset, tempBuff);

				check_set_filebuff_state(tempBuff);

				contInfo[0] = file_buffer_getStrtOffset(tempBuff) + file_buffer_getTotalLen(tempBuff);
				contInfo[1] =  tempBuff->endOffset;
				file_buffer_init_node(newfileBuf, contInfo, -1, SOCKET_NODE, SBData, 0);
				/* Attach new node after current node */
				newfileBuf->next = tempBuff->next;
				tempBuff->next = newfileBuf;
				TIZEN_LOGD("New Node Created [%x] and Total length [%llu]", newfileBuf, file_buffer_getTotalLen(newfileBuf));
				retval = B_TRUE;
			}
			else
			{
				retval = B_FALSE;
			}
		}
	}
	pthread_mutex_unlock(&(tempBuff->mut));
	pthread_mutex_unlock(&(fileMgr->mutex));

	return retval;
}

