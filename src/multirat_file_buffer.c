#include "multirat_process.h"
#include "multirat_file_buffer.h"
#include "multirat_conf.h"


void file_buffer_init(fileBuffer *fbuffer, uint32 brafMode)
{
	fbuffer->socketId = -1;
	fbuffer->offset = 0;
	fbuffer->startOffset = 0;
	fbuffer->endOffset = 0;
	fbuffer->totalLen = 0;
	fbuffer->appReadLen = 0;
	fbuffer->interface = 0;
	fbuffer->readFp = NULL;
	fbuffer->writeFp = NULL;
	fbuffer->file_flush_offset = 0;
	fbuffer->fThread_read = 0;
	fbuffer->nodeType = FILE_NODE;
	fbuffer->state = NODE_STATE_NOT_READ;
	fbuffer->next = NULL;
	fbuffer->bRafMode = brafMode;
	pthread_mutex_init(&(fbuffer->mut), NULL);
}

void file_buffer_exit(fileBuffer *fbuffer)
{
	TIZEN_LOGD("File %p", fbuffer);
	if(fbuffer->readFp != NULL)
	{
		fclose(fbuffer->readFp);
		fbuffer->readFp = NULL;
	}
	if(fbuffer->writeFp != NULL)
	{
		if(!fbuffer->bRafMode)
			fclose(fbuffer->writeFp);
		fbuffer->writeFp = NULL;
	}
	if(strlen(fbuffer->filePath) != 0)
	{
		int32 status = remove(fbuffer->filePath);
		if(status == 0)
		{
			TIZEN_LOGD("File [%s] Deleted Successfully", fbuffer->filePath);
			TIZEN_LOGD("Node [%s] Memory [%x] Type [%u] Start Offset [%llu] end Offset [%llu] total length [%llu]", fbuffer->filePath, fbuffer, fbuffer->nodeType, fbuffer->startOffset, fbuffer->endOffset, fbuffer->totalLen);
		}
		else
		{
			TIZEN_LOGD("Unable to delete the file [%s] Error Number [%d] [%s]", fbuffer->filePath, errno, strerror(errno));
		}
		memset(fbuffer->filePath,0,200);
	}
	if(fbuffer->socketId >= 0)
	{
		CLOSE_SOCKET(fbuffer->socketId);
		fbuffer->socketId = 0;
	}
	fbuffer->state = NODE_STATE_CLEARED;

	pthread_mutex_destroy(&(fbuffer->mut));
}

void file_buffer_init_node(fileBuffer *fbuffer, int64 *chunkInfo, int32 socketId, uint32 nodeType, SmartBondingData *SBData, uint32 fThread_read)
{
	uint32 brafMode = SBData->bRafMode;
	fbuffer->state = NODE_STATE_DOWNLOADING;

	fbuffer->startOffset = chunkInfo[0];
	fbuffer->endOffset = chunkInfo[1];

	fbuffer->totalLen = chunkInfo[1] - chunkInfo[0] + 1;

	fbuffer->socketId = socketId;
	fbuffer->nodeType = nodeType;
	fbuffer->bRafMode = brafMode;
	if(!brafMode)
	{
		memset(fbuffer->filePath,0,200);
		sprintf(fbuffer->filePath,"%s%d%s%lld%s%lld","/opt/usr/media/",getpid(),"-",chunkInfo[0],"-",chunkInfo[1]);
		TIZEN_LOGD("Created File [%s]", fbuffer->filePath);

		fbuffer->writeFp = fopen(fbuffer->filePath,"w");
		if(fbuffer->writeFp == NULL)
		{
			TIZEN_LOGD("unable to open(write) file");
		}

		fbuffer->readFp = fopen(fbuffer->filePath,"r");
		if(fbuffer->readFp == NULL)
		{
			TIZEN_LOGD("unable to open(read) file");
		}
		fbuffer->fThread_read = fThread_read;
	}
	else
	{
		fbuffer->readFp = NULL;
		/*RAF mode file is already opening to same common file, so just align the file pointer */
		fbuffer->writeFp = SBData->raFileMngr.writeFD2;
		if(NULL == fbuffer->writeFp)
		{
			TIZEN_LOGD("SBData[%p] ERROR SBData->raFileMngr.writeFD2 is NULL for [%s]", SBData, SBData->rafFileName);
		}
		else
		{
			if( -1 == fseek(fbuffer->writeFp,chunkInfo[0],SEEK_SET))
			{
				TIZEN_LOGD("SBData[%p] ERROR [%s] fseek [%llu] failed", SBData, SBData->rafFileName, chunkInfo[0]);
			}
		}
	}
	TIZEN_LOGD("Node Memory [%x] Type [%d] Start Offset [%llu] end Offset [%llu] total length [%llu]", fbuffer, fbuffer->nodeType, fbuffer->startOffset, fbuffer->endOffset, fbuffer->totalLen);
}

void file_buffer_reinit_node(fileBuffer *fbuffer, uint32 socket, uint32 nodeType)
{
	fbuffer->state = NODE_STATE_DOWNLOADING;
	fbuffer->nodeType = nodeType;
	if(fbuffer->socketId > 0)
	{
		CLOSE_SOCKET(fbuffer->socketId);
	}
	fbuffer->socketId = -1;
	if(socket > 0)
	{
		fbuffer->socketId = socket;
	}
	TIZEN_LOGD("Node [%s] Memory [%x] Type [%u] Start Offset [%llu] end Offset [%llu] total length [%llu]", fbuffer->filePath, fbuffer, fbuffer->nodeType, fbuffer->startOffset, fbuffer->endOffset, fbuffer->totalLen);
}



void file_buffer_add(fileBuffer *fbuffer, int8 *buff, uint64 size, int64 *chunkInfo, uint64 rcvdRsp, SmartBondingData *SBData)
{
	pthread_mutex_lock(&(fbuffer->mut));
	TIZEN_D_LOGD("Enter write Data into FILE [%llu]", size);

	if(fbuffer->offset == 0)
	{
		TIZEN_LOGD("Started Writing into File Node [%x] Total Length [%llu]", fbuffer, file_buffer_getTotalLen(fbuffer));
	}

	if(fbuffer->offset == file_buffer_getTotalLen(fbuffer))
	{
		TIZEN_LOGD("File Node [%x] Total Length [%llu] is Completed",fbuffer, file_buffer_getTotalLen(fbuffer));
		fbuffer->state = NODE_STATE_FULL_READ;
	}
	if(size != fwrite(buff,1,size, fbuffer->writeFp))
	{
		TIZEN_LOGD("Error: File Node [%x] Write size [%llu] failed ",fbuffer, size);
	}

	if(fbuffer->bRafMode)
		fflush(fbuffer->writeFp);

	fbuffer->offset = fbuffer->offset + size;

	if(fbuffer->offset == file_buffer_getTotalLen(fbuffer))
	{
		TIZEN_LOGD("File Node [%x] Total Length [%llu] is Completed",fbuffer, file_buffer_getTotalLen(fbuffer));
		fbuffer->state = NODE_STATE_FULL_READ;
	}
	pthread_mutex_unlock(&(fbuffer->mut));
	TIZEN_D_LOGD("Exit write Data into FILE [%llu]", size);
}

void file_buffer_read_from_file(fileBuffer *fbuffer, int8 *buff, uint64 *size)
{
	uint32 bytesCanBeRead = 0;
	uint32 minLen = 0;
	uint32 freadLen = 0;
	pthread_mutex_lock(&(fbuffer->mut));
	TIZEN_D_LOGD("File Node [%x] size [%llu] read start", fbuffer, *size);

	if(fbuffer->appReadLen == 0)
	{
		TIZEN_LOGD("Started Reading From File Node [%x] Total Length [%llu]", fbuffer, file_buffer_getTotalLen(fbuffer));
	}
	
	bytesCanBeRead  = fbuffer->offset - fbuffer->appReadLen;
	minLen = MIN(bytesCanBeRead, *size);

	if(fbuffer->bRafMode)
	{
		if(bytesCanBeRead > 0xffffffff)
		{
			bytesCanBeRead = 0xffffffff; /*as sb_read_data return in u32bit*/
			TIZEN_LOGD("File Node [%x] Total Length [%llu] bytesCanBeRead is greater than 0xffffffff", fbuffer, file_buffer_getTotalLen(fbuffer));
		}
		*size = bytesCanBeRead;
		freadLen = bytesCanBeRead;
	}
	else
	{
		if(fbuffer->file_flush_offset < fbuffer->offset)
		{
			fbuffer->file_flush_offset = fbuffer->offset;
			fflush(fbuffer->writeFp);
			TIZEN_LOGD("Flush File [%x]", fbuffer);
		}
		freadLen = fread(buff, 1, minLen, fbuffer->readFp);
		*size = freadLen;
	}

	fbuffer->appReadLen = fbuffer->appReadLen + freadLen;

	if(fbuffer->appReadLen == file_buffer_getTotalLen(fbuffer))
	{
		TIZEN_LOGD("File Node [%x] Total Length [%llu] is Completed", fbuffer, file_buffer_getTotalLen(fbuffer));
		fbuffer->state = NODE_STATE_CLEARED;
	}
	pthread_mutex_unlock(&(fbuffer->mut));
	TIZEN_D_LOGD("File Node [%x] size [%llu] is read done", fbuffer, *size);
}

void  file_buffer_read_from_socket(fileBuffer *fbuffer, uint32 size)
{
	pthread_mutex_lock(&(fbuffer->mut));

	if(fbuffer->appReadLen == 0)
	{
		TIZEN_LOGD("Started Reading From Socket Node [%x] Total Length [%llu]", fbuffer, file_buffer_getTotalLen(fbuffer));
	}

	fbuffer->appReadLen = fbuffer->appReadLen + size;
	fbuffer->offset = fbuffer->offset + size;
	if(fbuffer->offset == file_buffer_getTotalLen(fbuffer))
	{
		TIZEN_LOGD("Socket Node [%x] Total Length [%llu] is Completed", fbuffer, file_buffer_getTotalLen(fbuffer));
		fbuffer->state = NODE_STATE_CLEARED;
	}
	pthread_mutex_unlock(&(fbuffer->mut));
}

uint32 file_buffer_getState(fileBuffer *fbuffer)
{
	return fbuffer->state;
}

uint32 file_buffer_getType(fileBuffer *fbuffer)
{
	return fbuffer->nodeType;
}

uint64 file_buffer_noOfRspBytes(fileBuffer *fbuffer)
{
	return ((fbuffer->offset - fbuffer->appReadLen));
}

uint64 file_buffer_getTotalLen(fileBuffer *fbuffer)
{
	return fbuffer->totalLen;
}

uint64 file_buffer_getStrtOffset(fileBuffer *fbuffer)
{
	return fbuffer->startOffset;
}

uint64 file_buffer_getEndOffset(fileBuffer *fbuffer)
{
	return fbuffer->endOffset;
}

uint64 file_buffer_getOffset(fileBuffer *fbuffer)
{
	return fbuffer->offset;
}

uint32 file_buffer_getSocketId(fileBuffer *fbuffer)
{
	return fbuffer->socketId;
}

uint32 file_buffer_getNodeType(fileBuffer *fbuffer)
{
	return fbuffer->nodeType;
}

void file_buffer_setTotalLen(int newLen, fileBuffer *fbuffer)
{
	fbuffer->totalLen = newLen;
	TIZEN_LOGD("Node [%s] Memory [%x] Type [%d] Start Offset [%llu] end Offset [%llu] total length [%llu]",
		fbuffer->filePath, fbuffer, fbuffer->nodeType, fbuffer->startOffset, fbuffer->endOffset, fbuffer->totalLen);
}

uint64 file_buffer_getReadRspLen(fileBuffer *fbuffer)
{
	return fbuffer->appReadLen;
}

void check_set_filebuff_state(fileBuffer *tempBuff)
{
	if(tempBuff->offset == file_buffer_getTotalLen(tempBuff))
	{
		TIZEN_LOGD("File Node [%x] Total Length [%llu] is Already Written", tempBuff, file_buffer_getTotalLen(tempBuff));
		tempBuff->state = NODE_STATE_FULL_READ;
	}

	if(tempBuff->appReadLen == file_buffer_getTotalLen(tempBuff))
	{
		TIZEN_LOGD("File Node [%x] Total Length [%llu] is Already Completed", tempBuff, file_buffer_getTotalLen(tempBuff));
		tempBuff->state = NODE_STATE_CLEARED;
	}
}

