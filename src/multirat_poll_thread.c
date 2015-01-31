#include "multirat_SB_http.h"
#include "multirat_poll_thread.h"
#include "multirat_process.h"
#include "multirat_conf.h"
#include "multirat_watch_dog_thread.h"
#include "multirat_libapi.h"
#include "multirat_file_manager.h"
#include "multirat_file_stream.h"

PollThread* PollThread_init()
{
	PollThread *PollThrd = malloc(sizeof(PollThread));
	if(PollThrd == NULL)
	{
		TIZEN_LOGD("Error !!! curl thread allocation failed [%d] [%s]", errno, strerror(errno));
		return NULL;
	}
	memset(PollThrd,0,sizeof(PollThread));
	return PollThrd;
}

void PollThread_start(SmartBondingData *SBData)
{
	int32 ECode = 0;
	pthread_t thread = 0;

	if ((ECode = pthread_create(&thread, NULL, PollThread_entry_function,(void *)SBData)) != 0)
	{
		TIZEN_LOGD("Error !!! creating pthread [%d] [%s]", errno, strerror(errno));
		PollThread_exit(SBData->PollThrd);
		SBData->PollThrd = NULL;
	}
	else
	{
		TIZEN_LOGD("SBData [%p] Poll Thread Started", SBData);
		SBData->PollThrd->threadStatus = THREAD_INIT;
		SBData->PollThrd->threadId = thread;
	}
}

void *PollThread_entry_function(void *pArg)
{
	SmartBondingData *SBData = (SmartBondingData *)pArg;
	if(SBData)
	{
		PollThread_run_thread(SBData);
	}
	return NULL;
}

void PollThread_exit(PollThread *PollThrd)
{
	TIZEN_LOGD("Poll Thread Exit called");
	if(PollThrd != NULL)
	{
		if(PollThrd->threadStatus == THREAD_INIT)
			usleep(100000);
		PollThrd->threadStatus = THREAD_FINISH;

		if(0 != PollThrd->threadId)
			pthread_join(PollThrd->threadId,NULL);
		PollThrd->threadId = 0;
		free(PollThrd);
		PollThrd = NULL;
	}
	TIZEN_LOGD("Poll Thread Exit done");
}

void PollThread_run_thread(SmartBondingData *SBData)
{
	uint32 nbytes = 0;
	PollThread *PollThrd = SBData->PollThrd;
	char readbuffer[NOTI_TRIGGER_LENGTH + 1] = "\0";

	TIZEN_LOGD("SBData[%p] Poll Thread Run", SBData);
	PollThrd->threadStatus = THREAD_RUNNING;
	/* Poll for the Data on Noti Pipe Fd */
	while(PollThrd->threadStatus != THREAD_FINISH)
	{
		TIZEN_D_LOGD("SBData[%p] Waiting For Data on Notification Pipe Fd", SBData);

		PollThread_poll(SBData->noti_pipefd[0], SBData, 1000);

		if(PollThrd->threadStatus == THREAD_FINISH)
		{
			TIZEN_LOGD("SBData[%p] Exiting Poll Thread",SBData);
			return;
		}

	/* Read the Data from the Noti Pipe Fd */
		nbytes = read(SBData->noti_pipefd[0], readbuffer, NOTI_TRIGGER_LENGTH);
		nbytes = nbytes; /* Just to remove warnings */
		TIZEN_D_LOGD("SBData[%p] Read Data from Notification Pipe Fd [%s] Length [%d]",SBData, readbuffer, nbytes);

		/* Wait on Socket or PIPE fd */

		if(((SBData->response_body_read < SBData->expectedbytes) || (SBData->expectedbytes == 0) || (SBData->fStreamFileBufferReady == 0)))
		{
			TIZEN_D_LOGD("SBData[%p] Waiting For Data on Socket", SBData);
			PollThread_poll(SBData->socket_fd, SBData, 10);
			/* Write Into Trigger Pipe Fd */
			TIZEN_D_LOGD("SBData [%p] Write Data to Trigger Pipe Fd [%s]", SBData, NOTI_TRIGGER);
			nbytes = write(SBData->trigger_pipefd[1], NOTI_TRIGGER, NOTI_TRIGGER_LENGTH);
		}
		else
		{
			TIZEN_D_LOGD("SBData[%p] Waiting For Data on Node", SBData);
			PollThread_poll_buffer(SBData);
			/* Write Into Trigger Pipe Fd */
			TIZEN_D_LOGD("SBData[%p] Write Data to Trigger Pipe Fd [%s]", SBData, NOTI_TRIGGER);
			nbytes = write(SBData->trigger_pipefd[1], NOTI_TRIGGER, NOTI_TRIGGER_LENGTH);
		}
	}
	PollThrd->threadStatus = THREAD_FINISH;
}
