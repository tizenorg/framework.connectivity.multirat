#include "multirat_SB_http.h"
#include "multirat_process.h"
#include "multirat_decode_http.h"
#include "multirat_libapi.h"
#include "multirat_data_buffer.h"
#include "multirat_conf.h"
#include "multirat_watch_dog_thread.h"
#include "multirat_watchthread.h"
#include "multirat_poll_thread.h"
#include "multirat_multisocket.h"
#include "multirat_file_stream.h"
#include "multirat_file_manager.h"

#define TIME_ELAPSED_SINCE_LAST_TEMP_READ_IN_SECS 3

uint32 sb_get_cached_chunk(struct SmartBondingHandler *SBHandler, int8* buffer, uint32 len)
{
	if((buffer == NULL) || (!len))
	{
		TIZEN_LOGD("SBHandler[%p] Buffer Null", SBHandler);
		return SB_ERR;
	}
	if(SBHandler != NULL)
	{
		if(SBHandler->SBData != NULL)
		{
			buffer = memcpy(buffer, SBHandler->SBData->FileData, len);
			TIZEN_LOGD("SBHandler[%p] FileData [%s]", SBHandler, buffer);
			return SB_OK;
		}
	}
	return SB_ERR;
}

void sb_set_direct_write_mode(struct SmartBondingHandler *SBHandler)
{
	if(SBHandler != NULL )
	{
		if(SBHandler->SBData != NULL)
		{
			TIZEN_LOGD("SBHandler[%p] Setting RAF Mode", SBHandler);
			SBHandler->SBData->bRafMode = B_TRUE;
		}
	}
	return;
}

uint32 sb_set_direct_filename(struct SmartBondingHandler *SBHandler, int8 *buffer, uint32 len)
{
	TIZEN_LOGD("SBHandler[%p] Setting Direct Write File Name", SBHandler);
	if(SBHandler == NULL)
	{
		return SB_ERR;
	}
	if((buffer != NULL))
	{
		if(pthread_mutex_trylock(SBHandler->lock)!= 0)
		{
			TIZEN_LOGD("SBHandler[%p] Error !!! trylock failed, session closed by another thread [%d] [%s]",
							SBHandler, errno, strerror(errno));
			return SB_ERR;
		}

		if(SBHandler->SBData != NULL)
		{
			SmartBondingData *SBData = SBHandler->SBData;
			randomFileManager *raFileMngr = &(SBData->raFileMngr);
			httpReq *req = &(SBData->req);
			httpResp *resp = &(SBData->resp);
			if(!SBData->bRafMode)
			{
				TIZEN_LOGD("SBHandler[%p] RAF Mode Not Set", SBHandler);
				pthread_mutex_unlock(SBHandler->lock);
				return SB_ERR;
			}
			memcpy(SBData->rafFileName,buffer,len);

			// Random Access File Creation
			if((SBData->req.ifRange != NULL))
			{
				raFileMngr->writeFD1= fopen(SBData->rafFileName,"r+");
			}
			else
			{
				raFileMngr->writeFD1= fopen(SBData->rafFileName,"wb");
			}
			if(raFileMngr->writeFD1 == NULL)
			{
				TIZEN_LOGD("SBHandler[%p] Unable to open RAF File:writeFD1 file [%s] Failed", SBHandler, SBData->rafFileName);
				pthread_mutex_unlock(SBHandler->lock);
				return SB_ERR;
			}

			// Random Access File Creation
			if((req->ifRange != NULL))
			{
				raFileMngr->writeFD2= fopen(SBData->rafFileName,"r+");
			}
			else
			{
				raFileMngr->writeFD2= fopen(SBData->rafFileName,"wb");
			}
			if(raFileMngr->writeFD2 == NULL)
			{
				TIZEN_LOGD("SBHandler[%p] Unable to open RAF File:writeFD2 file [%s] Failed", SBHandler, SBData->rafFileName);
				fclose(raFileMngr->writeFD1);
				raFileMngr->writeFD1 = NULL;
				pthread_mutex_unlock(SBHandler->lock);
				return SB_ERR;
			}

			TIZEN_LOGD("SBHandler[%p] Created RAF File [%s]", SBHandler, SBData->rafFileName);

			raFileMngr->rspRead = SBData->startOffset;

			TIZEN_D_LOGD("SBHandler[%p] Random File:Seeking to this position:[%llu]", SBHandler, raFileMngr->rspRead);
			if(-1 == fseek(raFileMngr->writeFD1,raFileMngr->rspRead,SEEK_SET))
			{
				TIZEN_LOGD("SBHandler[%p] [%s] fseek [%llu] failed", SBHandler, SBData->rafFileName, raFileMngr->rspRead);
			}
			fwrite((void*)(resp->resp_buff_body + resp->resp_header_length),SBData->response_body_read, 1, raFileMngr->writeFD1);
			fflush(raFileMngr->writeFD1);
			raFileMngr->rspRead = raFileMngr->rspRead + SBData->response_body_read;
			TIZEN_LOGD("SBHandler[%p] random file:totoal bytes read [%llu], response_body_read [%llu]", SBHandler, raFileMngr->rspRead, SBData->response_body_read);

			if((SBData->enableMultiRat) && (NULL == SBData->cthread))
			{
				/*watchdog cthread is being created */
				SBData->cthread = cthread_init();
				/*watchdog cthread is initialised */
				cthread_start_thread(SBData);
				TIZEN_D_LOGD ("SBHandler[%p] MultiRat enabled, waiting for to start multi socket", SBHandler);
			}
			pthread_mutex_unlock(SBHandler->lock);
			return SB_OK;
		}
		pthread_mutex_unlock(SBHandler->lock);
	}
	return SB_ERR;
}

/* Smart Bonding Handler Initialisation */
struct SmartBondingHandler *smart_bonding_handler_init(void)
{
	SmartBondingData *SBData = NULL;

	struct SmartBondingHandler *SBHandler = malloc(sizeof(struct SmartBondingHandler));
	if(SBHandler == NULL)
	{
		TIZEN_LOGD("Error !!! SBHandler malloc failed [%d] [%s]", errno, strerror(errno));
		return NULL;
	}
	memset(SBHandler, 0, sizeof(struct SmartBondingHandler));

	pthread_mutex_t *lock = malloc(sizeof(pthread_mutex_t));
	if(lock == NULL)
	{
		TIZEN_LOGD("Error !!! Mutex Lock malloc failed [%d] [%s]", errno, strerror(errno));
		free(SBHandler);
		return NULL;
	}
	memset(lock, 0, sizeof(pthread_mutex_t));
	SBHandler->lock = lock;

	if (pthread_mutex_init(SBHandler->lock, NULL) != 0)
	{
		TIZEN_LOGD("Error !!! mutex init failed [%d] [%s]", errno, strerror(errno));
		free(SBHandler->lock);
		free(SBHandler);
		return NULL;
	}

	SBData = (SmartBondingData *)malloc(sizeof(SmartBondingData));

	if(SBData == NULL)
	{
		pthread_mutex_destroy(SBHandler->lock);
		free(SBHandler->lock);
		free(SBHandler);
		TIZEN_LOGD("Error !!! SBData allocation failure [%d] [%s]", errno, strerror(errno));
		return NULL;
	}

	memset(SBData, 0, sizeof(SmartBondingData));
	SBHandler->SBData = SBData;
	SBData->socket_fd = -1;

	#ifdef TWO_CHUNK
	SBData->twoChunk = 1;
	TIZEN_LOGD("SBHandler[%p] SBData[%p] Two --Chunk", SBHandler, SBData);
	#endif

	if (pthread_mutex_init(&SBData->tempLock, NULL) != 0)
	{
		TIZEN_LOGD("Error !!! mutex init failed [%d] [%s]", errno, strerror(errno));
		pthread_mutex_destroy(SBHandler->lock);
		free(SBHandler->lock);
		free(SBData);
		free(SBHandler);
		return NULL;
	}

	if(SBData->twoChunk == 1)
	{
		if (pipe(SBData->trigger_pipefd) < 0)
		{
			TIZEN_LOGD("Error !!! pipe failed [%d] [%s]", errno, strerror(errno));
			pthread_mutex_destroy(SBHandler->lock);
			free(SBHandler->lock);
			free(SBData);
			free(SBHandler);
			return NULL;
		}

		/* Setting Socket NON_BLOCKING */
		if (fcntl(SBData->trigger_pipefd[0], F_SETFL, O_NONBLOCK) != 0)
		{
			TIZEN_LOGD("Error !!! failed to set pipe fd [0] as NON-BLOCKING [%d] [%s]", errno, strerror(errno));

			CLOSE_SOCKET(SBData->trigger_pipefd[0]);
			CLOSE_SOCKET(SBData->trigger_pipefd[1]);

			pthread_mutex_destroy(SBHandler->lock);
			free(SBHandler->lock);
			free(SBData);
			free(SBHandler);
			return NULL;
		}

		if (fcntl(SBData->trigger_pipefd[1], F_SETFL, O_NONBLOCK) != 0)
		{
			TIZEN_LOGD("Error !!! failed to set pipe fd [1] as NON-BLOCKING [%d] [%s]", errno, strerror(errno));

			CLOSE_SOCKET(SBData->trigger_pipefd[0]);
			CLOSE_SOCKET(SBData->trigger_pipefd[1]);

			pthread_mutex_destroy(SBHandler->lock);
			free(SBHandler->lock);
			free(SBData);
			free(SBHandler);
			return NULL;
		}

		TIZEN_LOGD("SBHandler[%p] Trigger PIPE Fd[0] [%d] Fd[1] [%d]", SBHandler, SBData->trigger_pipefd[0], SBData->trigger_pipefd[1]);

		if (pipe(SBData->noti_pipefd) < 0)
		{
			TIZEN_LOGD("Error !!! pipe failed [%d] [%s]", errno, strerror(errno));

			CLOSE_SOCKET(SBData->trigger_pipefd[0]);
			CLOSE_SOCKET(SBData->trigger_pipefd[1]);

			pthread_mutex_destroy(SBHandler->lock);
			free(SBHandler->lock);
			free(SBData);
			free(SBHandler);
			return NULL;
		}

		/* Setting Socket NON_BLOCKING */
		if (fcntl(SBData->noti_pipefd[0], F_SETFL, O_NONBLOCK) != 0)
		{
			TIZEN_LOGD("Error !!! failed to set pipe fd [0] as NON-BLOCKING [%d] [%s]", errno, strerror(errno));

			CLOSE_SOCKET(SBData->trigger_pipefd[0]);
			CLOSE_SOCKET(SBData->trigger_pipefd[1]);
			CLOSE_SOCKET(SBData->noti_pipefd[0]);
			CLOSE_SOCKET(SBData->noti_pipefd[1]);

			pthread_mutex_destroy(SBHandler->lock);
			free(SBHandler->lock);
			free(SBData);
			free(SBHandler);
			return NULL;
		}

		if (fcntl(SBData->noti_pipefd[1], F_SETFL, O_NONBLOCK) != 0)
		{
			TIZEN_LOGD("Error !!! failed to set pipe fd [1] as NON-BLOCKING [%d] [%s]", errno, strerror(errno));

			CLOSE_SOCKET(SBData->trigger_pipefd[0]);
			CLOSE_SOCKET(SBData->trigger_pipefd[1]);
			CLOSE_SOCKET(SBData->noti_pipefd[0]);
			CLOSE_SOCKET(SBData->noti_pipefd[1]);

			pthread_mutex_destroy(SBHandler->lock);
			free(SBHandler->lock);
			free(SBData);
			free(SBHandler);
			return NULL;
		}

		TIZEN_LOGD("SBHandler[%p] Notification PIPE Fd[0] [%d] Fd[1] [%d]", SBHandler, SBData->noti_pipefd[0], SBData->noti_pipefd[1]);
		SBData->Libfd = SBData->trigger_pipefd[0];
	}

	TIZEN_D_LOGD("Smart Bonding initialisation is done successfully Handler [%x]", SBHandler);
	return SBHandler;
}

void smart_bonding_handler_exit(struct SmartBondingHandler *SBHandler)
{
	pthread_mutex_t *mutex_lock = NULL;

	if(SBHandler != NULL)
	{
		mutex_lock = SBHandler->lock;
		/* Mutex Lock */
		pthread_mutex_lock(mutex_lock);
		TIZEN_LOGD("SBHandler[%p] Mutex Locked in SmartBonding Handler Exit", SBHandler);

		if(SBHandler->SBData != NULL)
		{
			smart_bonding_exit(SBHandler->SBData);
			SBHandler->SBData = NULL;
		}

		free(SBHandler);
		SBHandler =  NULL;
		pthread_mutex_unlock(mutex_lock);
		pthread_mutex_destroy(mutex_lock);
		TIZEN_LOGD("Mutex Lock Released in SmartBonding Handler Exit");
		free(mutex_lock);
	}
}

struct SmartBondingHandler *sb_request_send(int8 *http_req, uint32 timeout, struct sockaddr_storage *remote_info,
									 void (*LibraryCallbackFunction)(void *), void *LibSessionIdentifier)
{
	struct SmartBondingHandler *SBHandler = NULL;
	TIZEN_LOGD("FAILED as this API is not implemented");
	return SBHandler;
}

struct SmartBondingHandler *sb_request_send_sync(int8 *http_req, uint32 timeout, struct sockaddr_storage *remote_info)
{
	SmartBondingData *SBData = NULL;
	struct SmartBondingHandler *SBHandler = NULL;

	SBHandler = send_request(http_req, timeout, remote_info);

	if(SBHandler != NULL)
	{
		SBData =  (SmartBondingData *)(SBHandler->SBData);
		if(SBData != NULL)
		{
			SBData->sync = 1;
		}
	}
	TIZEN_LOGD("SBHandler[%p] sb_request_send exit", SBHandler);
	return SBHandler;
}

struct SmartBondingHandler *sb_request_send_curl(int8 *http_req, uint32 timeout, struct sockaddr_storage *remote_info)
{
	/* Code Removed */
	struct SmartBondingHandler *SBHandler = NULL;
	return SBHandler;
}

int32 sb_get_connection_status(struct SmartBondingHandler *SBHandler)
{
	TIZEN_LOGD("SBHandler[%p] Check Connection Status", SBHandler);
	if(SBHandler == NULL)
	{
		return CONNECTION_FAIL;
	}
	int32 status = get_connection_status(SBHandler->SBData);
	if(status == -1)
	{
		if(SBHandler->SBData->con_status == CONNECTION_WAIT)
		{
			TIZEN_LOGD("SBHandler[%p] Connection WAIT",SBHandler);
		}
		else if (SBHandler->SBData->con_status == CONNECTION_FAIL)
		{
			TIZEN_LOGD("SBHandler[%p] Connection Failed", SBHandler);
		}
	}
	else
	{
		TIZEN_LOGD("SBHandler[%p] Connected Successfully", SBHandler);
	}
	return SBHandler->SBData->con_status;
}

struct SmartBondingHandler *sb_request_connect_only_curl(uint32 timeout, struct sockaddr_storage *remote_info)
{
	SmartBondingData *SBData = NULL;
	struct SmartBondingHandler *SBHandler = NULL;

	SBHandler = curl_connect_request(timeout, remote_info);

	if(SBHandler != NULL)
	{
		TIZEN_LOGD("SBHandler[%p] Success", SBHandler);
		SBData =  SBHandler->SBData;
		if(SBData != NULL)
		{
			SBData->curl = 1;
		}
	}
	return SBHandler;
}

struct SmartBondingHandler *curl_connect_request(uint32 timeout, struct sockaddr_storage *remote_info)
{
	SmartBondingData *SBData = NULL;
	struct sockaddr_in serv_addr;
	struct sockaddr_in6 serv_addr_ip6;
	connection *conn = NULL;
	struct SmartBondingHandler *SBHandler = NULL;

	/* Creating SmartBonding Handler */
	SBHandler = smart_bonding_handler_init();
	if (SBHandler == NULL)
	{
		TIZEN_LOGD("Smart Bonding Handler Creation Failed");
		return NULL;
	}

	pthread_mutex_lock(SBHandler->lock);

	SBData = SBHandler->SBData;
	conn = &(SBData->conn);
	if(SBData->twoChunk == 1)
		SBData->status = MAIN_START;

	smart_bonding_init_speed(SBData);

	SBData->stat.startTime = get_time_in_microsec();

	/* Get the IP address and Port number of Remote Server */
	switch(remote_info->ss_family)
	{
		case AF_INET:
		memset(&serv_addr, 0, sizeof(struct sockaddr_in));
		memcpy(&serv_addr,(struct sockaddr_in *)remote_info,sizeof(struct sockaddr_in));

		inet_ntop(AF_INET,&(serv_addr.sin_addr),(char*)conn->ip_addr,INET_ADDRSTRLENG);
		conn->port = ntohs(serv_addr.sin_port);
		conn->ip_family = 0;  /*Ipv4 */
		break;

		case AF_INET6:

		memset(&serv_addr_ip6, 0, sizeof(struct sockaddr_in6));
		memcpy(&serv_addr_ip6,(struct sockaddr_in6 *)remote_info,sizeof(struct sockaddr_in6));
		inet_ntop(AF_INET6,&(serv_addr_ip6.sin6_addr),(char*)conn->ip_addr,INET_ADDRSTRLENG);
		conn->port = ntohs(serv_addr_ip6.sin6_port);
		conn->ip_family = 1;  /*Ipv6 */
		break;

		default:
		strncpy(conn->ip_addr, "Unknown AF", INET_ADDRSTRLENG);
		TIZEN_LOGD("SBHandler[%p] Error !!  Unknown Family name ..", SBHandler);
		pthread_mutex_unlock(SBHandler->lock);
		smart_bonding_handler_exit(SBHandler);
		return NULL;
	}

	SECURE_DB_INFO("SBHandler[%p] destination IP address [%s:%d]",SBHandler, conn->ip_addr, conn->port);

	memcpy(conn->ifaceInfo[SBData->interface_index].server_ip, conn->ip_addr, strlen(conn->ip_addr));
	conn->ifaceInfo[SBData->interface_index].server_port = conn->port;
	memcpy(conn->ifaceInfo[(SBData->interface_index + 1) % 2].server_ip, conn->ip_addr, strlen(conn->ip_addr));

	get_client_socket(SBData, timeout, &serv_addr, &serv_addr_ip6);

	if(SBData->socket_fd < 0)
	{
		TIZEN_LOGD("SBHandler[%p] Error !!! connect failed", SBHandler);
		pthread_mutex_unlock(SBHandler->lock);
		smart_bonding_handler_exit(SBHandler);
		return NULL;
	}

	pthread_mutex_unlock(SBHandler->lock);
	return SBHandler;
}
/* 0 if send error 1 if success */
int32 sb_request_send_only_curl(struct SmartBondingHandler * SBHandler, int8 *http_req_in, uint32 len)
{
	SmartBondingData *SBData = NULL;
	connection *conn = NULL;
	uint32 nbytes = 0;
	int8*  http_req = NULL;
	uint32 err = B_FALSE;

	if((http_req_in != NULL) && (len > 4))
	{
		http_req = malloc((sizeof (char)) * (len+1));
		if(http_req)
		{
			memset(http_req, 0, (len+1));
			memcpy(http_req, http_req_in, len);
		}
		else
		{
			TIZEN_LOGD("SBHandler[%p] malloc failed", SBHandler);
			err = B_TRUE;
		}
	}
	else
		err = B_TRUE;
	if(err == B_TRUE)
	{
		TIZEN_LOGD("SBHandler[%p] Invalid http_req_in or len<0 or malloc failed", SBHandler);
		return B_FALSE;
	}

	pthread_mutex_lock(SBHandler->lock);

	SBData = SBHandler->SBData;
	conn = &(SBData->conn);
	store_http_request(http_req, SBData);

	/* check if proxy is present for main socket interface */
	int32 len_header = -1;
	len_header = decode_http_find_str(http_req,"http://");
	if((len_header != -1) && (len_header <= 4))
	{
		TIZEN_LOGD("Main thread setting proxy Enable");

		/* The Server IP and Port Number is of Proxy */
		memcpy(conn->ifaceInfo[SBData->interface_index].proxy_addr, conn->ifaceInfo[SBData->interface_index].server_ip, strlen(conn->ip_addr));
		conn->ifaceInfo[SBData->interface_index].proxy_port = conn->port;

		conn->ifaceInfo[SBData->interface_index].proxyEnable = 1;
	}

	SBData->stat.main_thread_sendTime = get_time_in_sec();

	if (send(SBData->socket_fd, http_req, len, 0) < 0)
	{
		TIZEN_LOGD("SBHandler[%p] Error !!! HTTP request send is failed [%d] [%s]", SBHandler, errno, strerror(errno));
		pthread_mutex_unlock(SBHandler->lock);
		CLOSE_SOCKET(SBData->socket_fd);
		SBData->socket_fd = -1;
		free(http_req);
		return B_FALSE;
	}
	SECURE_DB_INFO("SBHandler[%p] HTTP request is sent successfully [%s]", SBHandler, http_req);

	if(SBData->twoChunk == 1)
	{
		/* Create Thread */
		SBData->PollThrd = PollThread_init();
		if(SBData->PollThrd != NULL)
		{
			PollThread_start(SBData);
		}
		else
		{
			pthread_mutex_unlock(SBHandler->lock);
			free(http_req);
			return B_FALSE;
		}
		TIZEN_D_LOGD("SBHandler[%p] Write Data to Notification Pipe Fd [%s]", SBHandler, NOTI_TRIGGER);
		nbytes = write(SBData->noti_pipefd[1], NOTI_TRIGGER, NOTI_TRIGGER_LENGTH);
		nbytes = nbytes; /*warning removal */
	}

	pthread_mutex_unlock(SBHandler->lock);
	free(http_req);
	return B_TRUE;
}

struct SmartBondingHandler *send_request(int8 *http_req, uint32 timeout, struct sockaddr_storage *remote_info)
{
	SmartBondingData *SBData = NULL;
	connection *conn = NULL;
	struct sockaddr_in serv_addr;
	struct sockaddr_in6 serv_addr_ip6;
	struct SmartBondingHandler *SBHandler = NULL;
	/* Creating SmartBonding Handler */
	TIZEN_LOGD("Init");
	SBHandler = smart_bonding_handler_init();
	if (SBHandler == NULL)
	{
		TIZEN_LOGD("Smart Bonding Handler Creation Failed");
		return NULL;
	}

	pthread_mutex_lock(SBHandler->lock);

	SBData = SBHandler->SBData;
	conn = &(SBData->conn);
	SBData->stat.startTime = get_time_in_microsec();

	/* Get the IP address and Port number of Remote Server */
	switch(remote_info->ss_family)
	{
		case AF_INET:
		memset(&serv_addr, 0, sizeof(struct sockaddr_in));
		memcpy(&serv_addr,(struct sockaddr_in *)remote_info,sizeof(struct sockaddr_in));

		inet_ntop(AF_INET,&(serv_addr.sin_addr),(char*)conn->ip_addr,INET_ADDRSTRLENG);
		conn->port = ntohs(serv_addr.sin_port);
		conn->ip_family = 0;  /*Ipv4 */
		break;

		case AF_INET6:

		memset(&serv_addr_ip6, 0, sizeof(struct sockaddr_in6));
		memcpy(&serv_addr_ip6,(struct sockaddr_in6 *)remote_info,sizeof(struct sockaddr_in6));
		inet_ntop(AF_INET6,&(serv_addr_ip6.sin6_addr),(char*)conn->ip_addr,INET_ADDRSTRLENG);
		conn->port = ntohs(serv_addr_ip6.sin6_port);
		conn->ip_family = 1;  /*Ipv6 */
		break;

		default:
		strncpy(SBData->conn.ip_addr, "Unknown AF", INET_ADDRSTRLENG);
		TIZEN_LOGD("SBHandler[%p] Error-Unknown Family name", SBHandler);
		break;
	}

	SECURE_DB_INFO("SBHandler[%p] destination IP address [%s:%d]",SBHandler, conn->ip_addr, conn->port);
	memcpy(conn->ifaceInfo[SBData->interface_index].server_ip, conn->ip_addr, strlen(conn->ip_addr));
	conn->ifaceInfo[SBData->interface_index].server_port = conn->port;
	memcpy(conn->ifaceInfo[(SBData->interface_index + 1) % 2].server_ip, conn->ip_addr, strlen(conn->ip_addr));

	/* Storing of HTTP Request */
	store_http_request(http_req, SBData);
	get_client_socket(SBData, timeout, &serv_addr,&serv_addr_ip6);
	if(SBData->socket_fd < 0)
	{
		TIZEN_LOGD("SBHandler[%p] Error !!! connect failed", SBHandler);
		pthread_mutex_unlock(SBHandler->lock);
		//CLOSE_SOCKET(SBData->socket_fd);
		smart_bonding_handler_exit(SBHandler);
		return NULL;
	}

	SBData->stat.main_thread_sendTime = get_time_in_sec();

	/* check if proxy is present for main socket interface */
	int32 len_header = -1;
	len_header = decode_http_find_str(http_req,"http://");
	if((len_header != -1) && (len_header <= 4))
	{
		TIZEN_LOGD("Main thread setting proxy Enable");
		/* The Server IP and Port Number is of Proxy */
		memcpy(conn->ifaceInfo[SBData->interface_index].proxy_addr, conn->ifaceInfo[SBData->interface_index].server_ip, strlen(conn->ip_addr));
		conn->ifaceInfo[SBData->interface_index].proxy_port = conn->port ;

		conn->ifaceInfo[SBData->interface_index].proxyEnable = 1;
	}

	if (send(SBData->socket_fd, http_req, strlen(http_req), 0) < 0)
	{
		TIZEN_LOGD("SBHandler[%p] Error-HTTP request send is failed [%d] [%s]", SBHandler, errno, strerror(errno));
		pthread_mutex_unlock(SBHandler->lock);
		CLOSE_SOCKET(SBData->socket_fd);
		SBData->socket_fd = -1;
		smart_bonding_handler_exit(SBHandler);
		return NULL;
	}
	SECURE_DB_INFO("SBHandler[%p] HTTP request is sent to server successfully [%s]", SBHandler, http_req);

	pthread_mutex_unlock(SBHandler->lock);
	return SBHandler;
}

void get_client_socket(SmartBondingData *SBData, uint32 timeout, struct sockaddr_in *serv_addr,struct sockaddr_in6 *serv_addr_ip6)
{
	int32 socket_fd = -1;
	int32 interface_index = -1;
	uint64 connect_start = 0;
	connection *conn = &(SBData->conn);
	connect_start = get_time_in_sec();

	while((get_time_in_sec() - connect_start) < timeout && (!SBData->cancel))
	{
		/* Creating a  Client Socket */
		if(is_both_interface_avail(conn->ifaceInfo, conn->ip_family))
		{
			if(-1 == interface_index)
			{
				interface_index = MAIN_SOCKET_DEFAULT;
			}
			SECURE_DB_INFO("SBData[%p] source IP address [%s]", SBData, conn->ifaceInfo[interface_index].ip);
			socket_fd = conn_get_socket_bind(conn->ifaceInfo[interface_index].ip,interface_index, conn->ip_family);
			if(socket_fd < 0)
			{
				TIZEN_LOGD("SBData[%p] Error !!! while creating socket", SBData);
				usleep(5000);
				interface_index = (interface_index + 1) % 2;
				continue;
			}
		}
		else
		{
			if(strlen(conn->ifaceInfo[1].ip) != 0)
			{
				TIZEN_LOGD("SBData[%p] Avilable Interface is LTE for Main Socket Connection", SBData);
				interface_index = 1;
			}
			else
			{
				TIZEN_LOGD("SBData[%p] Avilable Interface is Wi-Fi for Main Socket Connection", SBData);
				interface_index = 0;
			}


			if(SBData->conn.ip_family)
			{
				socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
			}
			else
			{
				socket_fd = socket(AF_INET, SOCK_STREAM, 0);
			}
			if (socket_fd < 0)
			{
				TIZEN_LOGD("SBData[%p] Error !!! client socket creation failed", SBData);
				continue;
			}
		}

		SBData->interface_index = interface_index;
		if(-1 == connServer(socket_fd, serv_addr, serv_addr_ip6,timeout, SBData)) // Disabled COnnectivity Feature
		{
			if(SBData->con_status == CONNECTION_FAIL)
			{
				TIZEN_LOGD("SBData[%p] Error !!! connect to server failed", SBData);
				CLOSE_SOCKET(socket_fd);
				socket_fd = -1;
				continue;
			}
			else if(SBData->con_status == CONNECTION_WAIT)
			{
				TIZEN_LOGD("SBData[%p] Connect in WAIT STATE", SBData);
				SBData->socket_fd = socket_fd;
				break;
			}
		}
		else
		{
			SBData->socket_fd = socket_fd;
			TIZEN_LOGD("SBData[%p] connection is done successfully [%d]", SBData, SBData->socket_fd);
		}
		break;
	}
	SBData->timeout =  30;
	return;
}

int32 sb_read_data(struct SmartBondingHandler *SBHandler, int8 *buffer, uint32 size, int32 *nread)
{
	int32 retval = SB_OK;
	uint64 temp_endTime = 0;
	SmartBondingData *SBData = NULL;
	StatDetails *stat = NULL;
	randomFileManager *raFileMngr = NULL;
	char readbuffer[NOTI_TRIGGER_LENGTH + 1] = "";
	uint32 nbytes = 0;
	httpResp *resp = NULL;
	if (SBHandler ==  NULL)
	{
		TIZEN_LOGD("SBHandler is NULL");
		return SB_ERR;
	}

	SBData = SBHandler->SBData;
	if (SBData == NULL)
	{
		TIZEN_LOGD("SBHandler[%p] SBData is NULL", SBHandler);
		return SB_ERR;
	}

	stat = &(SBData->stat);
	resp = &(SBData->resp);
	raFileMngr = &(SBData->raFileMngr);
	speedStat *sStat = &(SBData->sStat);

	if(pthread_mutex_trylock(SBHandler->lock)!= 0)
	{
		TIZEN_LOGD("SBHandler[%p] Error !!! trylock failed, session closed by another thread [%d] [%s]",
			SBHandler, errno, strerror(errno));
		return SB_ERR;
	}

	TIZEN_D_LOGD("SBHandler[%p] Mutex Locked sb_read_data", SBHandler);

	/* Read the Data from the Trigger Pipe Fd */
	nbytes = read(SBData->trigger_pipefd[0], readbuffer, NOTI_TRIGGER_LENGTH);
	TIZEN_D_LOGD("SBHandler[%p] Read Data from Trigger Pipe Fd [%s] Length [%d]", SBHandler, readbuffer, nbytes);

	/* Setting Flag for main sock read active state */
	stat->read_start_time = (get_time_in_microsec());
	SBData->read_state_check = MAIN_SOCK_READ_ACTIVE;

	/* Checking For Session Cancel Flag */
	if(SBData->cancel)
	{
		TIZEN_LOGD("SBHandler[%p] Error !!! cancel_session command is recieved", SBHandler);
		pthread_mutex_unlock(SBHandler->lock);
		return SB_ERR;
	}

	if(stat->tempTime == 0)
	{
		stat->tempTime = get_time_in_sec();
		temp_endTime = stat->tempTime;
	}
	else
	{
		temp_endTime = get_time_in_sec();
	}

	if((temp_endTime - stat->tempTime) > TIME_ELAPSED_SINCE_LAST_TEMP_READ_IN_SECS )
	{
		TIZEN_D_LOGD("SBHandler[%p] Main Thread GET TEMP", SBHandler);
		getTempLevel(SBData);
		stat->tempTime = temp_endTime;
	}
	if(SBData->twoChunk == 1)
	{
		if((SBData->bRafMode) && (!(SBData->response_check)))
		{
			size = size - SBData->response_check_length - DIRECT_WRITE_HEADER_LENGTH;
			TIZEN_LOGD("SBHandler[%p] Reducing the Size of Read Buffer to [%d]", SBHandler, size);
		}
		if((SBData->bRafMode) && (!(strlen(SBData->rafFileName))) && (SBData->response_check))
		{
			TIZEN_LOGD("SBHandler[%p] Response is Completed ... File Name Not set ... Sending Error", SBHandler);
			pthread_mutex_unlock(SBHandler->lock);
			return SB_ERR;
		}
		if(SBData->fStreamFileBufferReady)
		{
			retval = file_stream_read(buffer, size, SBData, nread);
			if(SBData->sStat.prev_read == MAIN_THREAD)
			{
				if((SB_ERR == retval) && ((SBData->response_check != 0) ||
						((SBData->response_check == 0) && (SBData->response_body_read == 0))))
				{
					TIZEN_LOGD("SBHandler[%p] Main Socket Exception", SBHandler);
					retval = handleMainSocExp(SBData, buffer, size, nread);
					SBData->poll_thread_noti_exception= 1;
				}
			}
		}
		else
		{
			retval = twoChunk_read_from_socket(SBData,buffer,size,nread);
		}
	}
	else
	{
		if(SBData->mSocketDataBufferReady)
		{
			retval = read_from_buffer(SBData,buffer,size,nread);
		}
		else
		{
			retval = read_from_socket(SBData,buffer,size,nread);
		}
	}
	if (*nread > 0)
	{
		SBData->response_body_read = SBData->response_body_read + *nread;

		SBData->stat.offsetForSpeed = SBData->stat.offsetForSpeed + *nread;
		TIZEN_D_LOGD("SBHandler[%p] Read Data [%llu]",SBHandler, SBData->response_body_read);

		if(SBData->response_check == 0)
		{
			start_watchdog(SBData, buffer, *nread);
		}
		if((!SBData->resp_complete)&& (SBData->twoChunk) && (SBData->bRafMode))
		{
			if(SBData->response_check == 0)
			{
				*nread = 0;
				TIZEN_LOGD("SBHandler[%p] Complete Response is not Received", SBHandler);
				pthread_mutex_unlock(SBHandler->lock);
				return SB_OK;
			}
			else if((SBData->response_check == 1) && (!SBData->enableMultiRat))
			{
				TIZEN_LOGD("SBHandler[%p] No Need to go for RAF", SBHandler);
				/* We Dont Need to Change the Header */
				SBData->bRafMode = B_FALSE;
				memcpy(buffer, resp->resp_buff_body, SBData->response_check_length);
				*nread = SBData->response_check_length;
				SBData->resp_complete = B_TRUE;
			}
			else if((SBData->response_check == 1) && (SBData->enableMultiRat))
			{
				TIZEN_LOGD("SBHandler[%p] We Need to Continue with RAF", SBHandler);
				/* We Need to Change the Header*/
				memcpy(buffer, resp->resp_buff, resp->resp_header_length);
				sprintf(buffer + resp->resp_header_length - 4, "%s%s%s", "\r\n",DIRECT_WRITE_HEADER, "\r\n\r\n");
				*nread = resp->resp_header_length + DIRECT_WRITE_HEADER_LENGTH ;
				SBData->resp_complete = B_TRUE;
				SECURE_DB_INFO("SBHandler[%p] Response Sent [%s]", SBHandler, buffer);
			}
		}
		if(SBData->twoChunk != 1)
		{
			if(!SBData->mSocketDataBufferReady)
			{
				sb_calc_speed(SBData);
			}
		}
		else
		{
			if(sStat->prev_read == MAIN_THREAD)
			{
				if(SBHandler->SBData->bRafMode)
				{
					if(raFileMngr->rspHeaderCheck == 1)
					{
						if(raFileMngr->writeFD1 == NULL)
						{
							TIZEN_LOGD("SBHandler[%p] FD1 null for [%s]", SBHandler, SBData->rafFileName);
							pthread_mutex_unlock(SBHandler->lock);
							return SB_ERR;
						}

						if(!sStat->prev_sock_read)
						{
							TIZEN_D_LOGD("SBHandler[%p] Random File:Seeking to this position:[%llu]", SBHandler, raFileMngr->rspRead);
							if(-1 == fseek(raFileMngr->writeFD1, raFileMngr->rspRead,SEEK_SET))
							{
								TIZEN_LOGD("SBHandler[%p] fseek [%llu] failed", SBHandler, raFileMngr->rspRead);
							}
							sStat->prev_sock_read = B_TRUE;
						}

						fwrite(buffer, *nread, 1, raFileMngr->writeFD1);
						fflush(raFileMngr->writeFD1);
						raFileMngr->rspRead = raFileMngr->rspRead + *nread ;
						TIZEN_D_LOGD("SBHandler[%p] Random file:Total bytes read [%llu], *nread is [%d]", SBHandler, raFileMngr->rspRead , *nread);
					}

					if(raFileMngr->rspHeaderCheck == 0)
					{
						if(SBData->response_check == 1)
							raFileMngr->rspHeaderCheck = 1;
					}
				}
				uint64 temp_history = 0;
				uint64 temp_data = 0;
				temp_data = sStat->recv_length[SBData->interface_index];
				sStat->recv_length[SBData->interface_index] = sStat->recv_length[SBData->interface_index] + *nread;
				if(sStat->start_recv_time[SBData->interface_index] == 0)
					sStat->start_recv_time[SBData->interface_index] = get_time_in_microsec();
				sStat->prev_recv_time[SBData->interface_index] = get_time_in_microsec();
				temp_history = (sStat->prev_recv_time[SBData->interface_index] - sStat->start_recv_time[SBData->interface_index])/1000000;
				if((sStat->timeArray[SBData->interface_index] < (MAX_HISTORY)) && (temp_history < MAX_HISTORY) && (temp_history > sStat->timeArray[SBData->interface_index]))
				{
					int i = 0;
					TIZEN_LOGD("SBHandler[%p] Infidx [%d] Array Index [%llu] Data [%llu]", SBHandler, SBData->interface_index, sStat->timeArray[SBData->interface_index], sStat->dataArray[SBData->interface_index][sStat->timeArray[SBData->interface_index]]);
					sStat->dataArray[SBData->interface_index][temp_history] = sStat->recv_length[SBData->interface_index];
					for( i = sStat->timeArray[SBData->interface_index] + 1 ;  i < temp_history; i++)
					{
						sStat->dataArray[SBData->interface_index][i] = temp_data;
					}
					sStat->timeArray[SBData->interface_index] = temp_history;
					TIZEN_LOGD("SBHandler[%p] Infidx [%d] Data History Time [%llu] Data [%llu]", SBHandler, SBData->interface_index, temp_history, sStat->dataArray[SBData->interface_index][temp_history]);
				}
				sStat->prev_read = FILE_THREAD;

				TIZEN_D_LOGD("SBHandler[%p] Speed Calculated [%d] Interface Data [%llu]", SBHandler, SBData->interface_index, SBData->sStat.recv_length[SBData->interface_index]);
			}
			else
			{
				if(SBHandler->SBData->bRafMode)
				{
					sStat->prev_sock_read = B_FALSE;
					raFileMngr->rspRead = raFileMngr->rspRead + *nread ;
				}
			}
		}
	}
	if(SBData->twoChunk == 1)
	{
		/* Write the Data to the Noti Pipe Fd */
		if(SBData->poll_thread_noti_exception != 1)
		{
			TIZEN_D_LOGD("SBHandler[%p] Write Data to Notification Pipe Fd [%s]", SBHandler, NOTI_TRIGGER);
			nbytes = write(SBData->noti_pipefd[1], NOTI_TRIGGER, NOTI_TRIGGER_LENGTH);
			nbytes = nbytes; /*warning removal */
		}
	}
	pthread_mutex_unlock(SBHandler->lock);
	TIZEN_D_LOGD("SBHandler[%p] Mutext Lock Released read from socket", SBHandler);
	return retval;
}

int32 twoChunk_read_from_socket(SmartBondingData *SBData,int8 *buffer, int32 size, int32 *my_nread)
{
	int32 readSocketData = size;
	int32 read_value = 0;
	int32 retval = 0;
	uint32 connClose = 0;
	if(SBData->enableMultiRat)
	{
		if (SBData->fileThreadStarted)
		{
			is_file_stream_read(SBData);
			if(SBData->fStreamFileBufferReady == B_TRUE)
			{
				read_value = file_stream_read(buffer, size, SBData, my_nread);
				if(read_value == SB_ERR)
					TIZEN_LOGD("SBData[%p] Error", SBData);
				if(SBData->sStat.prev_read == MAIN_THREAD)
				{
					if((SB_ERR == read_value) && ((SBData->response_check != 0) ||
							((SBData->response_check == 0) && (SBData->response_body_read == 0))))
					{
						TIZEN_LOGD("SBData[%p] Main Socket Exception", SBData);
						read_value = handleMainSocExp(SBData,buffer, readSocketData, my_nread);
					}
				}
				return read_value;
			}
			else
			{
				if ((SBData->expectedbytes > 0) && (SBData->response_body_read < SBData->expectedbytes))
				{
					readSocketData = MIN((SBData->expectedbytes - SBData->response_body_read), size );
					TIZEN_D_LOGD("SBData[%p] size[%d]", SBData, readSocketData);
				}
			}
		}
	}

	if(SBData->curlThrd != NULL)
	{
		if(SBData->curlThrd->threadStatus == THREAD_FINISH)
		{
			curlThread_exit(SBData->curlThrd);
			SBData->curlThrd = NULL;
			TIZEN_LOGD("SBData[%p] Socket File [%d]", SBData, SBData->socket_fd);
			if(SBData->socket_fd < 0)
			{
				TIZEN_LOGD("SBData[%p] ERROR !!! Time out in Curl", SBData);
				SBData->cancel = 1;
				return SB_ERR;
			}
			else
			{
				//newly added to curl main socket exception
				uint64 currChunkLen = SBData->resp.cLen - SBData->response_body_read ;
				retval = range_request_recv_rng_rsp_headers(SBData->socket_fd,
						size, (SBData->timeout * 1000), SBData->resp.instanceSize,
						currChunkLen, my_nread, buffer, SBData->resp.cLen, &connClose);
				if (HTTP_RSP_DECODING_SUCCESS != retval)
				{
					return SB_ERR;
				}
				SBData->mainSockExp = 0;
				reset_stats(&(SBData->stat));
				TIZEN_LOGD("SBData[%p] New Socket for Curl [%d]", SBData, SBData->socket_fd);
				if(*my_nread != 0)
				{
					if((SBData->node_exception == SOCKET_NODE_FORCE_EXCEPTION) || (SBData->node_exception == SOCKET_NODE_NORMAL_EXCEPTION))
						// This Can be Due to Normal Exception or Forced Exception
					{
						TIZEN_LOGD("SBData[%p] Need to update the Socket Node about New Socket and Offset [%d]",SBData, *my_nread);
						file_manager_update_socket_node((uint64)*my_nread, SBData);
						SBData->fStreamFileBufferReady =  B_TRUE;
						SBData->fileThreadStarted = B_TRUE;
						SBData->enableMultiRat = B_TRUE;
						SBData->node_exception = 0;
					}
					else if(SBData->node_exception ==  SOCKET_NORMAL_EXCEPTION)
					{
						SBData->node_exception = 0;
					}
					return SB_OK;
				}
			}
		}
		else
		{
			TIZEN_D_LOGD("SBData[%p] curl trying to connect", SBData);
			return SB_WOULD_BLOCK;
		}
	}
	read_value = file_stream_read_from_socket(SBData->socket_fd, buffer, readSocketData, my_nread, SBData, 0);
	TIZEN_D_LOGD("SBData[%p] Read Value [%d] and Size [%d] Socket [%d]", SBData, read_value, *my_nread, SBData->socket_fd);

	if((SB_ERR == read_value) && ((SBData->response_check != 0) ||
		((SBData->response_check == 0) && (SBData->response_body_read == 0))))
	{
		read_value = handleMainSocExp(SBData,buffer, readSocketData, my_nread);
		SBData->poll_thread_noti_exception = 1;
	}

	return read_value;
}

int32 read_from_socket(SmartBondingData *SBData,int8 *buffer, int32 size, int32 *my_nread)
{
	int32 read_value = 0;
	int32 readSocketData = size;

	if(SBData->enableMultiRat)
	{
		if (SBData->multiSocketThreadStarted)
		{
			uint32 retval = is_multirat_read(SBData);
			if(retval)
			{
				if(SBData->curl)
				{
					if(retval == CURL_TIMEOUT_MULTIRAT_READ)
						return SB_ERR;
					else if(retval == CURL_BLOCK_MULTIRAT_READ)
						return SB_WOULD_BLOCK;
				}
			}
			if(SBData->mSocketDataBufferReady == B_TRUE)
			{
				return read_from_buffer(SBData,buffer,readSocketData, my_nread);
			}
			else
			{
				if ((SBData->totalExpectedBytes > 0) && (SBData->response_body_read < SBData->totalExpectedBytes))
				{
					readSocketData = MIN((SBData->totalExpectedBytes - SBData->response_body_read), size );
					TIZEN_D_LOGD("SBData[%p] size[%d]", SBData, readSocketData);
				}
			}
		}
	}
	if(SBData->curl == 1)
	{
		TIZEN_D_LOGD("SBData[%p] Read the Data from Socket Curl [%d]", SBData, SBData->socket_fd);
		read_value = read_from_socket_curl(buffer, readSocketData, my_nread, SBData);

		if(read_value == SB_WOULD_BLOCK)
		{
			if(SBData->CurlStartTime == 0)
				SBData->CurlStartTime = get_time_in_sec();

			if((get_time_in_sec() - SBData->CurlStartTime) > SBData->timeout)
			{
				TIZEN_LOGD("SBData[%p] Curl Socket Read Timeout", SBData);
				return SB_ERR;
			}
		}

		if((read_value == SB_ERR) && (SBData->cancel == 1))
		{
			/* Return error if error is due to timeout */
			return SB_ERR;
		}

		if(read_value == SB_OK)
			SBData->CurlStartTime = 0;
	}
	else if(SBData->sync == 1)
	{
		TIZEN_D_LOGD("SBData[%p] Read the Data from Socket SYNC", SBData);
		read_value = read_from_socket_sync(buffer, readSocketData, my_nread, SBData);
	}

	if((SB_ERR == read_value) && ((SBData->response_check != 0) ||
			((SBData->response_check == 0) && (SBData->response_body_read == 0))))
	{
		read_value = handleMainSocExp(SBData,buffer, readSocketData, my_nread);
	}
	return read_value;
}

int32 handleMainSocExp(SmartBondingData *SBData, int8 *buffer, uint32 size, int32 *my_nread)
{
	int32 retval = 0;
	TIZEN_LOGD("SBData[%p] Main Socket Handle Exception", SBData);

	// We Can Support Exception only after Other Interface Proxy and DNS are updated Properly in watch Dog code
	if(SBData->twoChunk == 1)
	{
		if(SBData->watch_dog_complete == B_FALSE)
		return SB_ERR;
	}

	// We Can Support Exception as We are doing Polling on Separate Thread
	if(0 < SBData->socket_fd)
	{
		CLOSE_SOCKET(SBData->socket_fd);
		SBData->socket_fd = -1;
	}
	if(SBData->resp.acceptFlag == 0)
	{
		TIZEN_LOGD("SBData[%p] Main Socket Exception Server Does not Support Range Request", SBData);
		return SB_ERR;
	}

	SBData->mainSockExp = 1 ;

	if(SBData->sync == 1)
	{
		retval =  checkinterface_connect(SBData);;
		if(retval == 0)
		{
			if(SBData->socket_fd > 0)
			{
				CLOSE_SOCKET(SBData->socket_fd);
				SBData->socket_fd = -1;
			}
			retval = SB_ERR;
		}
		else
		{
			retval = read_from_socket_sync(buffer, size, my_nread, SBData);
		}
	}
	else if(SBData->curl == 1)
	{
		SBData->curlThrd = curlThread_init();
		if(SBData->curlThrd != NULL)
		{
			curlThread_start(SBData);
			retval = SB_WOULD_BLOCK;
		}
		else
			retval = SB_ERR;

	}
	return retval;
}

int32 read_from_socket_sync(int8 *buffer, uint32 size , int32 *my_nread, SmartBondingData *SBData)
{
	int32 retval = 0;
	uint32 connClose = 0;

	if(SBData->mainSockExp == 1)
	{
		uint64 currChunkLen = SBData->resp.cLen - SBData->response_body_read ;
		retval = range_request_recv_rng_rsp_headers(SBData->socket_fd, size, (SBData->timeout * 1000),
				SBData->resp.instanceSize, currChunkLen, my_nread, buffer, SBData->resp.cLen, &connClose);
		if (HTTP_RSP_DECODING_SUCCESS != retval)
		{
			return SB_ERR;
		}
		reset_stats(&(SBData->stat));
		SBData->mainSockExp = 0;
		if(*my_nread != 0)
			return SB_OK;
	}
	retval = recv(SBData->socket_fd,buffer,size,0);
	if(retval <= 0)
	{
		if((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			retval = conn_poll(SBData->socket_fd, SBData->timeout * 1000);
			if(retval <= 0)
			{
				TIZEN_LOGD("SBData[%p] Error !!! Main socket time out", SBData);
				return SB_ERR;
			}
			else
			{
				retval = recv(SBData->socket_fd, buffer, size, 0);
				if(retval <= 0)
				{
					TIZEN_LOGD("SBData[%p] Error !!! Main socket error in recv [%s] ",SBData,  strerror (errno));
					return SB_ERR;
				}
				*my_nread = retval;
				return SB_OK;
			}
		}
		else
		{
			TIZEN_LOGD("SBData[%p] Error !!! Main socket error [%s] ",SBData, strerror (errno));
			return SB_ERR;
		}
	}
	else
	{
		*my_nread = retval;
		return SB_OK;
	}
}

int32 read_from_socket_curl(int8 *buffer, uint32 size , int32 *my_nread, SmartBondingData *SBData)
{
	int32 retval = 0;
	uint32 connClose = 0;
	if(SBData->curlThrd != NULL)
	{
		if(SBData->curlThrd->threadStatus == THREAD_FINISH)
		{
			curlThread_exit(SBData->curlThrd);
			SBData->curlThrd = NULL;
			if(SBData->socket_fd < 0)
			{
				TIZEN_LOGD("SBData[%p] ERROR !!! Time out in Curl", SBData);
				SBData->cancel = 1;
				return SB_ERR;
			}
			else
			{
				//newly added to curl main socket exception
				uint64 currChunkLen = SBData->resp.cLen - SBData->response_body_read ;
				retval = range_request_recv_rng_rsp_headers(SBData->socket_fd,
						size, (SBData->timeout * 1000), SBData->resp.instanceSize,
						currChunkLen, my_nread, buffer, SBData->resp.cLen, &connClose);
				if (HTTP_RSP_DECODING_SUCCESS != retval)
				{
					return SB_ERR;
				}
				SBData->mainSockExp = 0;
				reset_stats(&(SBData->stat));
				TIZEN_LOGD("SBData[%p] New Socket for Curl [%d]", SBData, SBData->socket_fd);
				if(*my_nread != 0)
					return SB_OK;
			}
		}
		else
		{
			TIZEN_D_LOGD("SBData[%p] curl trying to connect", SBData);
			return SB_WOULD_BLOCK;
		}
	}
	retval = recv(SBData->socket_fd, buffer, size,0);
	if(retval <= 0)
	{
		if((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			return SB_WOULD_BLOCK;
		}
		else
		{
			TIZEN_LOGD("SBData[%p] Error !!! Main socket error [%d] [%s] returning SB_ERR", SBData, errno, strerror (errno));
			return SB_ERR;
		}
	}
	*my_nread = retval;
	return SB_OK;
}

int32 sb_session_close(struct SmartBondingHandler *SBHandler)
{
	SmartBondingData *SBData = NULL;
	if(SBHandler == NULL)
	{
		TIZEN_LOGD("SBHandler is NULL");
		return B_FALSE;
	}
	SBData = (SmartBondingData *)SBHandler->SBData;
	if (SBData != NULL)
	{
		TIZEN_LOGD("SBHandler[%p] SBData[%p] Smart Bonding Session Close RAF[%d] RespBodyRead [%llu] contetlen [%llu]",
			SBHandler, SBData, SBData->bRafMode, SBData->response_body_read, SBData->content_length);
		SBData->cancel = 1;
	}

	smart_bonding_handler_exit(SBHandler);
	return 1;
}

int32 checkinterface_connect(SmartBondingData *SBData)
{
	int32 socket = -1;
	int32 status = 0;
	uint32 length = 0;
	uint32 interface_index = 0;
	uint64 startTime = 0;
	int8 *newReq = NULL;
	connection *conn = &(SBData->conn);

	startTime = get_time_in_sec();
	if(SBData->twoChunk == 1)
	{
		if(SBData->node_exception == SOCKET_NODE_FORCE_EXCEPTION)
			interface_index = (SBData->interface_index + 1) % 2;
		else
			interface_index = SBData->interface_index;
	}
	else
		interface_index = SBData->interface_index;
	while((get_time_in_sec() - startTime) < SBData->timeout && (!SBData->cancel))
	{
		if(interface_index == 1)
		{
			if(!is_interface_up(WIFI_IFACE_NAME, conn->ifaceInfo, conn->ip_family))
			{
				if(!is_interface_up(LTE_IFACE_NAME, conn->ifaceInfo, conn->ip_family))
				{
					usleep(100000);
					continue;
				}
				else
				{
					interface_index = 1;
				}
			}
			else
			{
				interface_index = 0;
			}
		}
		else
		{
			if(!is_interface_up(LTE_IFACE_NAME, conn->ifaceInfo, conn->ip_family))
			{
				if(!is_interface_up(WIFI_IFACE_NAME, conn->ifaceInfo, conn->ip_family))
				{
					usleep(100000);
					continue;
				}
				else
				{
					interface_index = 0;
				}
			}
			else
			{
				interface_index = 1;
			}
		}

		socket = conn_get_socket_bind(conn->ifaceInfo[interface_index].ip, interface_index, conn->ip_family);
		if(socket < 0)
		{
			return B_FALSE;
		}

		if(SBData->twoChunk == 1)
		{
			if((SBData->file_status != NO_REDIVISION) && (SBData->fStream != NULL) && (SBData->fStream->fileMgr != NULL))
			{
				SBData->fStream->fileMgr->interface[MAIN_THREAD] = interface_index;
				SBData->fStream->fileMgr->interface[FILE_THREAD] = (interface_index + 1) % 2;
			}
			SBData->status = MAIN_IO_EXCEPTION;
		}

		SBData->socket_fd = socket;
		SBData->interface_index = interface_index;
		TIZEN_LOGD("SBData[%p] Check Interface Fd [%d]", SBData, SBData->socket_fd);
		if(SBData->watch_dog_complete)
		{
			TIZEN_LOGD("SBData[%p] Watch Dog is Completed Lets Take Watch Dog DNS", SBData);

			if(SBData->req.Rangeheader != NULL)
			{
				newReq = get_new_req(SBData->req.request[interface_index], SBData->req.rangeStart,
						SBData->response_body_read, 0, &length, strlen(SBData->req.request[interface_index]), SBData->conn.ifaceInfo[interface_index].proxyEnable);
			}
			else
			{
				newReq = get_new_req(SBData->req.request[interface_index], 0, SBData->response_body_read, 0,
						&length, strlen(SBData->req.request[interface_index]), SBData->conn.ifaceInfo[interface_index].proxyEnable);
			}
		}
		else
		{
			if(SBData->req.Rangeheader != NULL)
			{
				newReq = get_new_req(SBData->req.req_buff_wo_range,
						SBData->req.rangeStart,
						SBData->response_body_read, 0, &length, SBData->req.req_wo_len, SBData->conn.ifaceInfo[interface_index].proxyEnable);
			}
			else
			{
				newReq = get_new_req(SBData->req.req_buff, 0,
						SBData->response_body_read, 0, &length, SBData->req.reqLen, SBData->conn.ifaceInfo[interface_index].proxyEnable);
			}
		}
		if(newReq == NULL)
		{
			CLOSE_SOCKET(socket);
			SBData->socket_fd = -1;
			break;
		}

		status = send_req(newReq, length, socket, interface_index, SBData);

		if(status == 0)
		{
			CLOSE_SOCKET(socket);
			SBData->socket_fd = -1;
			free(newReq);
			newReq = NULL;
			continue;
		}
		else
			break;
	}

	if(NULL != newReq)
	{
		free(newReq);
		newReq = NULL;
	}
	if(SBData->twoChunk == 1)
	{
		/* Write the Data to the Noti Pipe Fd */

		if(SBData->poll_thread_noti_exception != 0)
		{
			uint32 nbytes = 0;
			TIZEN_D_LOGD("SBData[%p] Write Data to Notification Pipe Fd [%s]", SBData, NOTI_TRIGGER);
			nbytes = write(SBData->noti_pipefd[1], NOTI_TRIGGER, NOTI_TRIGGER_LENGTH);
			nbytes = nbytes; /*warning removal */
			SBData->poll_thread_noti_exception = 0;
		}
	}
	return status;
}
