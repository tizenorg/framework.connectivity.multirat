#ifndef FILEBUFFER_H_
#define FILEBUFFER_H_

#include "multirat_SB_http.h"

void file_buffer_init(fileBuffer *fbuffer, uint32 brafMode);

void file_buffer_exit(fileBuffer *fbuffer);

void file_buffer_init_node(fileBuffer *fbuffer, int64 *chunkInfo, int32 socketId, uint32 nodeType, SmartBondingData *SBData, uint32 fThread_read);

void file_buffer_reinit_node(fileBuffer *fbuffer, uint32 socket, uint32 nodeType);

void file_buffer_add(fileBuffer *fbuffer, int8 *buff, uint64 size,int64 *chunkInfo, uint64 rcvdRsp, SmartBondingData *SBData);

void file_buffer_read_from_file(fileBuffer *fbuffer, int8 *buff, uint64 *size);

void  file_buffer_read_from_socket(fileBuffer *fbuffer, uint32 size);

uint32 file_buffer_getState(fileBuffer *fbuffer);

uint64 file_buffer_noOfRspBytes(fileBuffer *fbuffer);

uint64 file_buffer_getTotalLen(fileBuffer *fbuffer);

uint64 file_buffer_getStrtOffset(fileBuffer *fbuffer);

uint64 file_buffer_getEndOffset(fileBuffer *fbuffer);

uint64 file_buffer_getOffset(fileBuffer *fbuffer);

uint32 file_buffer_getSocketId(fileBuffer *fbuffer);

uint32 file_buffer_getNodeType(fileBuffer *fbuffer);

uint32 file_buffer_getType(fileBuffer *fbuffer);

void file_buffer_setTotalLen(int newLen, fileBuffer *fbuffer);

uint64 file_buffer_getReadRspLen(fileBuffer *fbuffer);

int8* file_buffer_getFile(fileBuffer *fbuffer);

void check_set_filebuff_state(fileBuffer *tempBuff);
#endif

