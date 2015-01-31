#include "multirat_SB_http.h"
#include "multirat_watchthread.h"
#include "multirat_process.h"
#include "multirat_conf.h"
#include "multirat_watch_dog_thread.h"
#include "multirat_libapi.h"
#include "multirat_file_manager.h"
#include "smartbonding-client.h"

#define MIN_TIME_TO_CHECK_STOP_SLOW  (6 * 1000 );
#define MIN_TIME_TO_CHECK_STOP_SLOW_FOR_LOW_TH  (7 * 1000 )
#define MIN_TIME_TO_CHECK_DATA_READ (2 * 1000 * 1000)
#define MAX_TIME_TO_CHECK_DATA_READ (30 * 1000 * 1000)
#define TIME_CHECK_SPEED ( 1 * 1000 * 1000)
#define THRESHOLD_OF_SLOW_TH  (10 * 1024 * 1024 / 1000)
#define OFFSET_TIME_TO_CHECK_STOP_SLOW  (3 * 1000)
#define MIN_RATIO_FOR_ONLY_ONE_INF_0V1  (5)
#define MIN_RATIO_FOR_ONLY_ONE_INF_1V0  (5)

#define WLAN_INT 0
#define LTE_INT 1

void smart_bonding_init_speed(SmartBondingData *SBData)
{
	int i = 0;
	int j = 0;
	speedStat *sStat = &(SBData->sStat);
	for(i = 0; i < MAX_INTERFACES; i++)
	{
		SBData->speed[i] = 0;
		sStat->prev_recv_time[i] = 0;
		sStat->slow_start_length[i] = 0;
		sStat->slow_start_time[i] = 0;
		sStat->recv_length[i] = 0;
		sStat->start_recv_time[i] = 0;

		/* Stores initial data to measure loss of bytes due to slowstart tcp phase */
		sStat->timeArray[i] = 0;
		for(j = 0; j<MAX_HISTORY; j++)
		{
			sStat->dataArray[i][j] = 0;
		}
	}
	TIZEN_LOGD("Init Success");
}

uint64  getSpeedWithOffset(int id, SmartBondingData *SBData)
{
	speedStat *sStat = &(SBData->sStat);
	if((sStat->recv_length[id] == 0) || (sStat->slow_start_length[id] == 0))
		return 0;
	uint64 speed = 0;
	uint64 data = (sStat->recv_length[id] - sStat->slow_start_length[id]);
	uint64 time = ((sStat->prev_recv_time[id] - sStat->start_recv_time[id])/1000) - sStat->slow_start_time[id];
	TIZEN_D_LOGD("Data [%llu] time [%llu]", data, time);
	if(time <= 0 || data <= 0)
	{
		return 0;
	}
	else
	{
		speed = ((data/time)  * 8 * 1000);
		TIZEN_D_LOGD("speed with offset [%llu]", speed);
		return speed;
	}
}

uint64  getSpeedWithoutOffset(int id, SmartBondingData *SBData)
{
	speedStat *sStat = &(SBData->sStat);
	if((sStat->recv_length[id] == 0) || (sStat->slow_start_length[id] == 0))
		return 0;
	uint64 speed = 0;
	uint64 data = (sStat->recv_length[id]);
	uint64 time = ((sStat->prev_recv_time[id] - sStat->start_recv_time[id])/1000);
	TIZEN_D_LOGD("Data [%llu] time [%llu]", data, time);
	if(time <= 0 || data <= 0)
	{
		return 0;
	}
	else
	{
		speed = (((data)/time) * 8 * 1000);
		TIZEN_D_LOGD("speed without offset [%llu]", speed);
		return speed;
	}
}


uint32 speed_calc_check_compare(uint64 *speed_time , SmartBondingData *SBData)
{
	uint64 current_time = (get_time_in_microsec());
	uint64 difftime0 = 0;
	uint64 difftime1 = 0;
	speedStat *sStat = &(SBData->sStat);
	uint32 id0 = SBData->interface_index;
	uint32 id1 = (SBData->interface_index + 1) % 2;

	if(sStat->start_recv_time[id0] != 0)
		difftime0 = (current_time - sStat->start_recv_time[id0])/1000;

	if(sStat->start_recv_time[id1] != 0)
		difftime1 = (current_time - sStat->start_recv_time[id1])/1000;

	if((current_time - *speed_time) < TIME_CHECK_SPEED)
	{
		usleep(20000);
		return B_TRUE;
	}

	if((abs((get_time_in_microsec() - SBData->stat.read_start_time)) > (MIN_TIME_TO_CHECK_DATA_READ)) &&  (abs((get_time_in_microsec() - SBData->stat.read_start_time)) < (MAX_TIME_TO_CHECK_DATA_READ)))
	{
		SBData->read_state_check = MAIN_SOCK_READ_INACTIVE;
		TIZEN_LOGD(" MAIN READ INACTIVE - >  FILE THREAD SUD STOP READ ");
	}

	else if((abs(get_time_in_microsec() - SBData->stat.read_start_time)) >= (MAX_TIME_TO_CHECK_DATA_READ))
	{
		TIZEN_LOGD("current time [%llu] read tme [%llu]", get_time_in_microsec(), SBData->stat.read_start_time);
		TIZEN_LOGD("MAIN SOCK READ DOWN..   EXIT FILE THREAD");
		SBData->fStream->compRspRcvdFlag = 0;
		return B_FALSE;
	}

	TIZEN_D_LOGD("ID0 [%u] ID1 [%u]", id0, id1);
	TIZEN_D_LOGD("start time [%llu] [%llu]", sStat->start_recv_time[id0], sStat->start_recv_time[id1]);
	TIZEN_LOGD("Diff Times Zero [%llu] one [%llu] Recv length Zero [%llu] Receive length one [%llu]", difftime0, difftime1, sStat->recv_length[0], sStat->recv_length[1]);

	sStat->start_speed_check_time = current_time;

	*speed_time = (get_time_in_microsec());

	if((sStat->slow_start_length[id0] == 0) &&  (difftime0 >= OFFSET_TIME_TO_CHECK_STOP_SLOW))
	{
		uint64 initSpeed0 = 0;
		sStat->slow_start_length[id0] = sStat->recv_length[id0];
		sStat->slow_start_time[id0] = difftime0;
		initSpeed0 = sStat->slow_start_time[id0] == 0 ? 0 : (sStat->slow_start_length[id0] * 8 * 1000) / sStat->slow_start_time[id0];
		if(initSpeed0 > THRESHOLD_OF_SLOW_TH)
		{
			sStat->minTimeToCheckStopSlow[id0] = MIN_TIME_TO_CHECK_STOP_SLOW;
		}
		else
		{
			sStat->minTimeToCheckStopSlow[id0] = MIN_TIME_TO_CHECK_STOP_SLOW_FOR_LOW_TH;
		}
		TIZEN_LOGD("Min Time [%llu] Slow Start for id0 [%d]", sStat->minTimeToCheckStopSlow[id0], id0);
	}

	if((SBData->sStat.slow_start_length[id1] == 0) &&  (difftime1 >= OFFSET_TIME_TO_CHECK_STOP_SLOW))
	{
		long initSpeed1 = 0;
		sStat->slow_start_length[id1] = sStat->recv_length[id1];
		sStat->slow_start_time[id1] = difftime1;
		initSpeed1 = sStat->slow_start_time[id1] == 0 ? 0 : sStat->slow_start_length[id1] * 8 *1000 / sStat->slow_start_time[id1];
		if(initSpeed1 > THRESHOLD_OF_SLOW_TH)
		{
			sStat->minTimeToCheckStopSlow[id1] = MIN_TIME_TO_CHECK_STOP_SLOW;
		}
		else
		{
			sStat->minTimeToCheckStopSlow[id1] = MIN_TIME_TO_CHECK_STOP_SLOW_FOR_LOW_TH;
		}
		TIZEN_LOGD("Min Time [%llu] Slow Start for id1 [%d]", sStat->minTimeToCheckStopSlow[id1], id1);
	}

	if((sStat->minTimeToCheckStopSlow[id0] > 0) && (difftime0 >= sStat->minTimeToCheckStopSlow[id0]))
	{
		uint64 sp0 = 0;
		uint64 sp1 = 0;
		uint64 spNoOffset1 = 0;
		sp0 = getSpeedWithOffset(id0, SBData);
		sp1 = getSpeedWithOffset(id1, SBData);
		SBData->speed[id0] = sp0;
		SBData->speed[id1] = sp1;
		spNoOffset1 = getSpeedWithoutOffset(id1, SBData);

		TIZEN_LOGD("Wifi Speed [%u] LTE Speed [%u] sp0 [%llu] sp1 [%llu]", SBData->speed[0], SBData->speed[1], sp0, sp1);
		if((SBData->response_body_read < SBData->expectedbytes))
		{
			if((sStat->minTimeToCheckStopSlow[id1] > 0) && (((difftime1 >= sStat->minTimeToCheckStopSlow[id1])
				&& (sStat->slow_start_time[id1] != difftime1)
					&& (sp0 > MIN_RATIO_FOR_ONLY_ONE_INF_0V1 * sp1))
						|| ((spNoOffset1 <= 10) && (difftime1 >= sStat->minTimeToCheckStopSlow[id1]/ 2) && (sStat->recv_length[id1] > 0)
							&& (SBData->sStat.slow_start_time[id1] != difftime1))))
			{
				SBData->enableMultiRat = 0;
				SBData->fStream->compRspRcvdFlag = 0;
				TIZEN_LOGD("Close The File Thread");
				if(id0 == WLAN_INT)
				{
					TIZEN_LOGD("POP UP LTE SLOW");
					smart_bonding_notify_interface_usage("download_booster_lte_slow");
				}
				else
				{
					TIZEN_LOGD("POP UP WI-FI SLOW");
					smart_bonding_notify_interface_usage("download_booster_wifi_slow");
				}
				return B_FALSE;
			}

			else if((sStat->minTimeToCheckStopSlow[id1] > 0) && (difftime1 >= sStat->minTimeToCheckStopSlow[id1]
					&& MIN_RATIO_FOR_ONLY_ONE_INF_1V0 >= 0 && sp1 > MIN_RATIO_FOR_ONLY_ONE_INF_1V0 * sp0 && sp0 > 0 && sp1 > 0))
			{
				SBData->file_status = NO_REDIVISION;
				TIZEN_LOGD("Close Main Socket and No Redivision in File");
				if(id0 == LTE_INT)
				{
					TIZEN_LOGD("POP UP LTE SLOW");
					smart_bonding_notify_interface_usage("download_booster_lte_slow");
				}
				else
				{
					TIZEN_LOGD("POP UP WI-FI SLOW");
					smart_bonding_notify_interface_usage("download_booster_wifi_slow");
				}
				CLOSE_SOCKET(SBData->socket_fd);
				return B_FALSE;
			}
		}
	}
	TIZEN_D_LOGD("Curr time [%llu] Interface 0 time [%llu] Interface 1 time [%llu]", current_time, SBData->sStat.prev_recv_time[0], SBData->sStat.prev_recv_time[1]);
	return B_TRUE;
}

void sb_calc_speed(SmartBondingData *SBData)
{
	uint64 diffTime = 0;
	uint64 currTime = get_time_in_microsec();
	StatDetails *stat = &(SBData->stat);

	if(stat->dataOffsetTime != 0)
	diffTime = (currTime - stat->dataOffsetTime)/ 1000;

	if(diffTime > 50)
	{
		if(stat->speedIndex == 100)
		{
			stat->speedIndex = 0;
		}
		stat->dataArr[stat->speedIndex] = stat->offsetForSpeed - stat->dataOffset;
		stat->timeArr[stat->speedIndex] = diffTime;
		stat->dataOffset = stat->offsetForSpeed;
		stat->dataOffsetTime = currTime;
		stat->speedIndex++;
		if((stat->dataStrtTime != 0) && (currTime - stat->dataStrtTime) > 5000000)
		{
			stat->mainSockSpeed = getAggSpeed(stat->dataArr,stat->timeArr);
			TIZEN_D_LOGD("Main socket Speed [%d]",stat->mainSockSpeed);
		}
	}
}

uint32 getAggSpeed(uint32 *dataArr,uint64 *timeArr)
{
	uint32 i = 0;
	uint32 aggData = 0;
	uint64 aggTime = 0;

	for(i = 0; i < 100; i++)
	{
		aggData = aggData + dataArr[i];
		aggTime = aggTime + timeArr[i];
	}
	return (uint32)((aggData * 8)/aggTime);
}

curlThread* curlThread_init()
{
	curlThread *curlThrd = malloc(sizeof(curlThread));
	if(curlThrd == NULL)
	{
		TIZEN_LOGD("Error !!! curl thread allocation failed [%d] [%s]", errno, strerror(errno));
		return NULL;
	}
	memset(curlThrd,0,sizeof(curlThread));
	curlThrd->threadId = 0;
	return curlThrd;
}

void curlThread_start(SmartBondingData *SBData)
{
	int32 ECode = 0;
	pthread_t thread = 0;

	if ((ECode = pthread_create(&thread, NULL, curlThread_entry_function,(void *)SBData)) != 0)
	{
		TIZEN_LOGD("SBData[%p] Error !!! creating pthread [%d] [%s]", SBData, errno, strerror(errno));
		curlThread_exit(SBData->curlThrd);
		SBData->curlThrd = NULL;
	}
	else
	{
		SBData->curlThrd->threadStatus = THREAD_INIT;
		SBData->curlThrd->threadId = thread;
	}
}

void *curlThread_entry_function(void *pArg)
{
	SmartBondingData *SBData = (SmartBondingData *)pArg;

	if(SBData)
	{
		curlThread_run_thread(SBData);
	}
	return NULL;
}

void curlThread_exit(curlThread *curlThrd)
{
	TIZEN_LOGD("Curl Thread Exit");
	if(curlThrd != NULL)
	{
		if(curlThrd->threadStatus == THREAD_INIT)
			usleep(100000);
		curlThrd->threadStatus = THREAD_FINISH;
		if(0 != curlThrd->threadId)
			pthread_join(curlThrd->threadId,NULL);
		curlThrd->threadId = 0;
		free(curlThrd);
		curlThrd = NULL;
	}
}

void curlThread_run_thread(SmartBondingData *SBData)
{
	int32 status = checkinterface_connect(SBData);
	if(status == 0)
	{
		if(SBData->socket_fd > 0)
		{
			CLOSE_SOCKET(SBData->socket_fd);
			SBData->socket_fd = -1;
		}
	}
	SBData->curlThrd->threadStatus =  THREAD_FINISH;
}
