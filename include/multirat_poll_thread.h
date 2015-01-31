#ifndef _POLL_THREAD_H_
#define _POLL_THREAD_H_

PollThread* PollThread_init();
void PollThread_start(SmartBondingData *SBData);
void *PollThread_entry_function(void *pArg);
void PollThread_exit(PollThread *PollThrd);
void PollThread_run_thread(SmartBondingData *SBData);

#endif
