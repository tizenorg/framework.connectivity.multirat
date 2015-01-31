#ifndef FILETHREAD_H_
#define FILETHREAD_H_

#include <pthread.h>

void file_thread_init(fileThread *fThread, SmartBondingData *SBData, fileStream *fStream);

uint32 file_thread_start(fileThread *fThread);

void *FileThreadCallBack(void *ptr);

void file_thread_run(fileThread *fThread);

int32 file_thread_range_request_recv_rng_rsp_headers(uint64 *bodyLen, char *blockSize,
                              uint64 currChunkLen, uint32 *connClose, fileThread *fThread);

int32 file_thread_rebuildReq(char *newRequest, int64 *chunkInfo, fileThread *fThread);

void file_thread_exit(fileThread *fThread);

int file_thread_handleIOExp(fileThread *fThread, uint32 *ifCount ,int32 iptype);

int file_thread_connet_server_interface(fileThread *fThread);

int file_thread_connect_server_interface_first(int32 result, fileThread *fThread);

int32 file_thread_range_request_recv_rng_rsp_headers_first_req(uint64 *bodyLen, char *blockSize, uint64 currChunkLen, uint32 *connClose, fileThread *fThread, int8 *rcvBuff, int32 lengthRcvd);
#endif /* FILETHREAD_H_ */

