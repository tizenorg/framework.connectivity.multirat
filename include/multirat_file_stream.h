#ifndef FILESTREAM_H_
#define FILESTREAM_H_

void file_stream_init(SmartBondingData *SBData);

uint32 file_stream_start(SmartBondingData *SBData);

int32 file_stream_read(int8 *buff, int32 maxAppLen, SmartBondingData *SBData, int32 *my_nread);

void file_stream_exit(fileStream *fStream);

int32 file_stream_read_from_socket(int32 socket, int8 *buff, uint64 toBeRead, int32 *tempLen, SmartBondingData *SBData, uint32 index);

void is_file_stream_read(SmartBondingData *SBData);

void PollThread_poll_buffer(SmartBondingData *SBData);
#endif /* FILESTREAM_H_ */
