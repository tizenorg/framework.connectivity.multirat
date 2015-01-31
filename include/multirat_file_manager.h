#ifndef FILEMANAGER_H_
#define FILEMANAGER_H_

#include "multirat_SB_http.h"

void file_manager_init(fileStream *fStream, fileManager *fileMgr);

fileBuffer *file_manager_getNextChunkForFileThread(int64 *chunkInfo, SmartBondingData *SBData);

fileBuffer *file_manager_getDownloadingNode(fileManager *fileMgr);

fileBuffer *file_manager_getDownloadingFileNode(fileManager *fileMgr);

void file_manager_setSpeed(uint32 index, uint32 speed, SmartBondingData *SBData);

void file_manager_exit(fileManager *fileMgr);

fileBuffer *file_manager_getReadingNode(fileManager *fileMgr);

uint32 file_manager_get_file_thread_interface(fileManager *fileMgr);

uint32 file_manager_get_main_thread_interface(fileManager *fileMgr);

uint32 file_manager_check_main_thread_status(fileManager *fileMgr);

fileBuffer *file_manager_getNextChunkForFileThread_new(int64 *chunkInfo, SmartBondingData *SBData, uint32 index);

uint32 file_manager_divideCont(uint64 remCont, int64 *contInfo, fileManager *fileMgr, uint32 nodeType);

uint32 file_manager_divideRemCont(uint64 remCont, fileManager *fileMgr, uint32 nodeType);

fileBuffer * file_manager_get_next_chunk_handle_file_io_exception(fileManager *fileMgr, int64 *chunkInfo);

fileBuffer * file_manager_get_next_chunk_handle_main_complete(fileManager *fileMgr, int64 *chunkInfo);

fileBuffer * file_manager_get_next_chunk_handle_file_complete(fileManager *fileMgr, int64 *chunkInfo);

void file_manager_update_socket_node(uint64 offset, SmartBondingData *SBData);

void file_manager_SwitchSocketNoData(fileBuffer *tempBuff, fileManager *fileMgr);

fileBuffer *file_manager_SwitchSocketData(fileBuffer *tempBuff, fileManager *fileMgr, int64 *chunkInfo, int ifacechange);

uint32 file_manager_file_node_block_handle(SmartBondingData *SBData);
#endif /* FILEMANAGER_H_ */

