#include "multirat_process.h"
#include "multirat_data_buffer.h"

void data_buffer_init(DataBuffer *dbuffer, uint32 noOfChunks, uint64 cthread)
{
	uint32 i = 0;
	DataBuffer *buff = NULL;

	for (i = 0; i< noOfChunks ;i++)
	{
		buff = dbuffer + i;
		buff->appReadLen = 0;
		buff->data = NULL;
		buff->offset = 0;
		buff->threadId = -1;
		buff->totalLen = 0;
		buff->estSpeed = 0;
		buff->socketId = 0;
		buff->state = STATE_NOT_READ;
		buff->cthread = cthread;
		memset(buff->filePath,0,200);
		pthread_mutex_init(&(buff->mut), NULL);
	}
}/* End of DataBuffer() */

void data_buffer_init_chunk(int32 threadId, uint32 size, int32 socketId, DataBuffer *dbuffer, int64 *chunkInfo)
{
#if 0
	dbuffer->data = (char*)malloc(size);
	if (NULL == dbuffer->data)
	{
		TIZEN_LOGD("Error !!! while allocating memory for dbuffer->data");
		return;
	}
	memset(dbuffer->data, 0, size);
	memset(dbuffer->filePath,0,200);
#endif
	sprintf(dbuffer->filePath,"%s%llu%s%llu%s%llu%s%llu","/opt/usr/media/",get_time_in_microsec(),"-",dbuffer->cthread,"-",chunkInfo[0],"-",chunkInfo[1]);

	TIZEN_LOGD("Created File %s", dbuffer->filePath);

	dbuffer->writeFp = fopen(dbuffer->filePath,"w");

	if(dbuffer->writeFp == NULL)
	{
		TIZEN_LOGD("unable to open(write) file");
	}

	dbuffer->readFp = fopen(dbuffer->filePath,"r");
	if(dbuffer->readFp == NULL)
	{
		TIZEN_LOGD("unable to open(read) file");
	}

	dbuffer->totalLen = size;
	dbuffer->threadId = threadId;
	dbuffer->socketId = socketId;
	dbuffer->state = STATE_OCCUPIED;
}/* End of initChunk() */

void data_buffer_reinit_chunk(int32 threadId, int32 socketId, DataBuffer *dbuffer)
{
	dbuffer->threadId = threadId;
	dbuffer->socketId = socketId;
	dbuffer->state = STATE_READING;
}/* End of reInitChunk() */

void data_buffer_add(uint32 size, int32 threadId, int8 *buff, DataBuffer *dbuffer)
{
	if (dbuffer->threadId != threadId)
	{
		return;
	}

	if ((size > 0) && (dbuffer->offset < dbuffer->totalLen))
	{
		pthread_mutex_lock(&(dbuffer->mut));
		if (dbuffer->offset == 0)
		{
			dbuffer->state = STATE_READING;
		}/* End of if */
		fwrite(buff, size, 1, dbuffer->writeFp);
		fflush(dbuffer->writeFp);
		dbuffer->offset = dbuffer->offset + size;

		if (dbuffer->offset == dbuffer->totalLen)
		{
			dbuffer->state = STATE_FULL_READ;
		}/* End of if */

		pthread_mutex_unlock(&(dbuffer->mut));
	}/* End of if */
	return;
}/* End of add() */

void data_buffer_freeBuffer(DataBuffer *dbuffer)
{
	int32 status = 0;
	dbuffer->state = STATE_CLEARED;
#if 0
	if (NULL != dbuffer->data)
	{
		free(dbuffer->data);
	}/* End of if */
	dbuffer->data = NULL;
#endif
	if(dbuffer->readFp != NULL)
	{
		fclose(dbuffer->readFp);
		dbuffer->readFp = NULL;
	}
	if(dbuffer->writeFp != NULL)
	{
		fclose(dbuffer->writeFp);
		dbuffer->writeFp = NULL;
	}
	if(strlen(dbuffer->filePath) != 0)
	{
		status = remove(dbuffer->filePath);
		if(status == 0)
		{
			TIZEN_LOGD("File %s Deleted Successfully", dbuffer->filePath);
		}
		else
		{
			TIZEN_LOGD("Unable to delete the file %s Error Number [%d] [%s]", dbuffer->filePath, errno, strerror(errno));
		}
		memset(dbuffer->filePath,0,200);
	}
}/* End of freeBuffer() */

void data_buffer_read_portion(int8 *buff, uint32 size, DataBuffer *dbuffer)
{
	uint32 minLen = 0;
	uint32 freadLen = 0;
	uint32 bytesCanBeRead  = 0;
	bytesCanBeRead  = dbuffer->offset - dbuffer->appReadLen;
	if (bytesCanBeRead > 0)
	{
		pthread_mutex_lock(&(dbuffer->mut));
		minLen = MIN(bytesCanBeRead, size);
		TIZEN_D_LOGD("Reading from File %s", dbuffer->filePath);
		freadLen = fread(buff, 1, minLen, dbuffer->readFp);
		dbuffer->appReadLen = dbuffer->appReadLen + freadLen;
		pthread_mutex_unlock(&(dbuffer->mut));
	}
	return;
}

void data_buffer_switch_socket(int32 threadId, uint32 otherSpeed, DataBuffer *dbuffer)
{
	dbuffer->threadId = threadId;
	dbuffer->estSpeed = otherSpeed;
	dbuffer->state = STATE_BLOCKED;

	/* closing current socket */
	close(dbuffer->socketId);
}

void data_buffer_exit(DataBuffer *dbuffer)
{
	int32 status = 0;
#if 0
	if (NULL != dbuffer->data)
	{
		free(dbuffer->data);
	}/* End of if */
	dbuffer->data = NULL;
#endif

	if(dbuffer->readFp != NULL)
	{
		fclose(dbuffer->readFp);
		dbuffer->readFp = NULL;
	}
	if(dbuffer->writeFp != NULL)
	{
		fclose(dbuffer->writeFp);
		dbuffer->writeFp = NULL;
	}
	if(strlen(dbuffer->filePath) != 0)
	{
		status = remove(dbuffer->filePath);
		if(status == 0)
		{
			TIZEN_LOGD("File %s Deleted Successfully", dbuffer->filePath);
		}
		else
		{
			TIZEN_LOGD("Unable to delete the file %s Error Number [%d] [%s]", dbuffer->filePath, errno, strerror(errno));
		}
		memset(dbuffer->filePath,0,200);
	}
	pthread_mutex_destroy(&(dbuffer->mut));
}


