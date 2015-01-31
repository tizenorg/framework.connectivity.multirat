#ifndef MULTIRAT_WATCHTHREAD_H_
#define MULTIRAT_WATCHTHREAD_H_

void smart_bonding_init_speed(SmartBondingData *SBData);
uint32 speed_calc_check_compare(uint64 *speed_time , SmartBondingData *SBData);
void sb_calc_speed(SmartBondingData *SBData);
uint32 getAggSpeed(uint32 *dataArr,uint64 *timeArr);
void curlThread_run_thread(SmartBondingData *SBData);
void curlThread_exit(curlThread *curlThrd);
void *curlThread_entry_function (void *pArg);
void curlThread_start(SmartBondingData *SBData);
curlThread* curlThread_init();

#endif
