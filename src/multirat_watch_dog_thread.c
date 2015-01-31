#include "multirat_conf.h"
#include "multirat_process.h"
#include "multirat_libapi.h"
#include "multirat_watch_dog_thread.h"
#include "multirat_multisocket.h"
#include "multirat_decode_http.h"
#include "multirat_range_request_thread.h"
#include <vconf.h>
#include <vconf-keys.h>
#include "multirat_file_stream.h"
#include "multirat_file_manager.h"
#include "multirat_file_buffer.h"
#include "multirat_watchthread.h"

#ifdef TIZEN_UX_SUPPORT
#include "smartbonding-client.h"
#endif

void get_proxy_info(SmartBondingData *SBData, int interface_index)
{
	connection *conn =  &(SBData->conn);
	get_proxy_ip_port(conn->ifaceInfo[interface_index].proxy_addr, &(conn->ifaceInfo[interface_index].proxy_port));
	if(strlen(conn->ifaceInfo[interface_index].proxy_addr) != 0)
	{
		memset(SBData->conn.ifaceInfo[interface_index].server_ip,0,INET_ADDRSTRLEN);
		memcpy(conn->ifaceInfo[interface_index].server_ip, conn->ifaceInfo[interface_index].proxy_addr, strlen(conn->ifaceInfo[interface_index].proxy_addr));
		conn->ifaceInfo[interface_index].server_port = conn->ifaceInfo[interface_index].proxy_port;
		conn->ifaceInfo[interface_index].proxyEnable = B_TRUE;
	}
	else
	{
		conn->ifaceInfo[interface_index].server_port = 80;
	}
	get_dns_ip(conn->ifaceInfo[interface_index].dns_1, conn->ifaceInfo[interface_index].dns_2);

	SECURE_DB_INFO("Server/Proxy IP Address [%s]", conn->ifaceInfo[interface_index].server_ip);
	SECURE_DB_INFO("Server/Proxy Port [%d]", conn->ifaceInfo[interface_index].server_port);
	SECURE_DB_INFO("DNS 1 [%s]", conn->ifaceInfo[interface_index].dns_1);
	SECURE_DB_INFO("DNS 2 [%s]", conn->ifaceInfo[interface_index].dns_2);
}

int32 file_thread_FirstConnection(SmartBondingData *SBData, fileThread *fThread, int64 *chunkInfo, int8 *recv_buf, int32 *lengthRcvd)
{
	int8 *host = NULL;
	int32 socket = -1;
	uint32 redirect = 0;
	uint32 length = 0;
	uint32 retval_watch_dog = 1;
	int retval = -1;
	uint32 interface_index = 0;
	int8 *newReq = NULL;
	httpReq *req = &(SBData->req);
	struct hostent *h = NULL;
	struct sockaddr_in remote_addr;
	struct sockaddr_in6 remote_addr_ip6;
	httpResp httprsp;
	connection *conn =  &(SBData->conn);
	memset(&httprsp, 0, sizeof(httpResp));
	interface_index = (fThread->interface_index);

	SECURE_DB_INFO("Server IP Address [%s]", conn->ifaceInfo[SBData->interface_index].server_ip);
	get_proxy_info(SBData, interface_index);
	if(req->Rangeheader != NULL)
	{
		newReq = get_new_req(req->req_buff_wo_range, 0, chunkInfo[0], chunkInfo[1], &length, req->req_wo_len, conn->ifaceInfo[interface_index].proxyEnable);
	}
	else
	{
		newReq = get_new_req(req->req_buff, 0, chunkInfo[0], chunkInfo[1], &length, req->reqLen, conn->ifaceInfo[interface_index].proxyEnable);
	}

	SECURE_DB_INFO("HTTP New Req [%s]",newReq);

	if(!SBData->conn.ifaceInfo[interface_index].proxyEnable)
	{
		getHost(&host, newReq);
		if(NULL != host)
		{
			SECURE_DB_INFO("DNS Resolution for Proxy Case Host [%s]", host);
			if(!getDNSInfo(host, interface_index, SBData))
			{
				TIZEN_LOGD("DNS Resolution Failed for Interface [%d]", interface_index);
				free(host);
				if(newReq != NULL)
					free(newReq);
				return retval;
			}
		}
		else
		{
			if(newReq != NULL)
				free(newReq);
			return retval;
		}
	}

	while(*fThread->compRspRcvdFlag)
	{
		retval_watch_dog = 1;
		memset(recv_buf, 0, MAX_HEADERS_SIZE + 1);

		socket = conn_get_socket_bind(conn->ifaceInfo[interface_index].ip,interface_index,conn->ip_family);

		if(socket < 0)
		{
			if(NULL != host)
				free(host);
			if(newReq != NULL)
				free(newReq);
			return retval;
		}

		TIZEN_LOGD("File Thread Socket [%d]",socket);

		redirect ++;

		if(redirect > 3)
		{
			TIZEN_LOGD("No Of Redirections Exceeded");
			CLOSE_SOCKET(socket);
			if(NULL != host)
				free(host);
			if(newReq != NULL)
				free(newReq);
			return retval;
		}

		h = gethostbyname(conn->ifaceInfo[interface_index].server_ip);

		if(SBData->conn.ip_family)
		{
			memset(&remote_addr_ip6, 0, sizeof(struct sockaddr_in6));
			remote_addr_ip6.sin6_family = h->h_addrtype;
			memcpy((char *) &remote_addr_ip6.sin6_addr.s6_addr, h->h_addr_list[0], h->h_length);
			remote_addr_ip6.sin6_port = htons(conn->port);
		}
		else
		{
			memset(&remote_addr, 0, sizeof(struct sockaddr_in));
			remote_addr.sin_family = h->h_addrtype;
			memcpy((char *) &remote_addr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
			remote_addr.sin_port = htons(conn->port);
		}

		if(-1 == file_thread_connServer(socket, &remote_addr, &remote_addr_ip6, SBData->timeout, SBData))
		{
			CLOSE_SOCKET(socket);
			if(NULL != host)
				free(host);
			if(newReq != NULL)
				free(newReq);
			return retval;
		}

		TIZEN_LOGD("Connect Success in File Thread");

		if (-1 == send(socket, newReq, length, 0))
		{
			TIZEN_LOGD("File Thread got Exception during send [%s]", strerror (errno));
		}
		else
		{
			TIZEN_LOGD("Send HTTP Request Success in File Thread");
			memset(recv_buf, 0, MAX_HEADERS_SIZE + 1);
			while (*fThread->compRspRcvdFlag)
			{
				int32 len = 0;
				int32 offset = 0;
				int32 rcvdLen = 0;
				int32 headerLen = 0;

				if(file_thread_conn_poll(socket, SBData) <= 0)
				{
					TIZEN_LOGD("Error !!! File Thread pollfd failed Timeout or Fail or Exit");
					break;
				}

				rcvdLen = recv(socket, recv_buf + offset, MAX_HEADERS_SIZE - offset, 0);
				TIZEN_LOGD("Recvd length [%d]",rcvdLen);

				if (rcvdLen > 0)
				{
					len = decode_http_find_str(recv_buf, END_OF_HEADERS);
					if (-1 != len)
					{
						headerLen = len + 4;
						TIZEN_LOGD("Header length [%d]", headerLen);
						memset(&httprsp, 0, sizeof(httpResp));
						decode_http_rsp_init(recv_buf, headerLen, &httprsp);
						SECURE_DB_INFO("File Thread Response [%s]", httprsp.resp_buff);

						retval = process_http_rsp(&httprsp);
						if ((HTTP_RSP_REDIRECT  == retval) && (httprsp.location != NULL))
						{
							TIZEN_LOGD("Redirection Happening and New Location [%s]", httprsp.location);

							if(handleRedirection(httprsp.location, interface_index, &newReq, &length, SBData) == HTTP_RSP_DECODING_SUCCESS)
							{
								retval_watch_dog = 0;
								CLOSE_SOCKET(socket);
								socket = -1;
								retval = -1;
								break;
							}
							else
							{
								retval = -1;
								break;
							}
						}
						else if(HTTP_RSP_DECODING_SUCCESS != retval)
						{
							TIZEN_LOGD("HTTP Decoding Error");
							retval = -1;
							break;
						}
						retval = 0;
						TIZEN_LOGD("HTTP Response in File Trhead is SUCCESS");
						*lengthRcvd  = rcvdLen;
						break;
					}
					offset = offset + rcvdLen;
					if(offset >= MAX_HEADERS_SIZE)
					{
						retval = -1;
						break;
					}
				}
				else
				{
					/* Socket error */
					break;
				}
			}
			delete_http_rsp(&httprsp);
			if(retval_watch_dog == 1)
				break;
		}
	}

	TIZEN_LOGD("RETURN VALUE [%d]",retval);

	if(retval == -1)
	{
		if(socket > 0)
		{
			CLOSE_SOCKET(socket);
			socket = -1;
		}
		if(NULL != host)
			free(host);
		if(newReq != NULL)
			free(newReq);
		return retval;
	}
	if((store_interface_ip_request(newReq, SBData, interface_index) == 0))
	{
		SBData->watch_dog_complete = 1;
	}
	if(NULL != host)
		free(host);
	if(newReq != NULL)
		free(newReq);
	return socket;
}

int32 watchdog_test_connection_type(SmartBondingData *SBData)
{
	int8 *host = NULL;
	int32 socket = -1;
	int32 retval = 0;
	int32 connType = 0;
	uint32 redirect = 0;
	uint32 length = 0;
	uint32 retval_dns = 0;
	uint32 retval_watch_dog = 1;
	uint32 timeT2 = 0;
	uint32 resp_len  = 0;
	uint32 resp_offset = 0;
	uint32 interface_index = 0;
	uint64 endTime = 0;
	uint64 startTime = 0;
	uint64 contLength = 0;
	int8 recv_buf[MAX_HEADERS_SIZE + 1] = {0};
	int8 *newReq = NULL;
	httpReq *req = &(SBData->req);
	struct hostent *h = NULL;
	struct sockaddr_in remote_addr;
	struct sockaddr_in6 remote_addr_ip6;
	httpResp httprsp;
	connection *conn =  &SBData->conn;
	startTime = get_time_in_microsec();
	memset(&httprsp, 0, sizeof(httpResp));
	TIZEN_LOGD("WatchDog test");
	interface_index = (SBData->interface_index + 1) % 2;
	if(req->Rangeheader != NULL)
	{
		newReq = get_new_req(req->req_buff_wo_range, 0, 0, 1, &length, req->req_wo_len, conn->ifaceInfo[interface_index].proxyEnable);
	}
	else
	{
		newReq = get_new_req(req->req_buff, 0, 0, 1, &length, req->reqLen, conn->ifaceInfo[interface_index].proxyEnable);
	}
	TIZEN_LOGD("UID [%d]", getuid());
	memcpy(conn->ifaceInfo[SBData->interface_index].server_ip, conn->ip_addr, strlen(conn->ip_addr));
	memcpy(conn->ifaceInfo[interface_index].server_ip, conn->ip_addr, strlen(conn->ip_addr));

	SECURE_DB_INFO("Server IP Address [%s]", conn->ifaceInfo[SBData->interface_index].server_ip);

	SECURE_DB_INFO("HTTP New Req [%s]",newReq);
	getHost(&host, newReq);
	if(NULL != host)
	{
		SECURE_DB_INFO("DNS Resolution for Proxy Case Host [%s]", host);
		retval_dns = getDNSInfo(host, interface_index, SBData);
		free(host);
	}
	if(0 == retval_dns)
	{
		TIZEN_LOGD("DNS Resolution Failed for Interface [%d]", interface_index);
		free(newReq);
		return -1;
	}
	while(SBData->cthread->threadStatus != THREAD_FINISH)
	{
		retval_watch_dog = 1;

		socket = conn_get_socket_bind(conn->ifaceInfo[interface_index].ip,interface_index,conn->ip_family);

		if(socket < 0)
		{
			free(newReq);
			return -1;
		}

		TIZEN_LOGD("WatchDog Socket [%d]",socket);

		redirect ++;
		if(redirect > 3)
		{
			TIZEN_LOGD("No Of Redirections Exceeded");
			CLOSE_SOCKET(socket);
			return -1;
		}

		h = gethostbyname(conn->ifaceInfo[interface_index].server_ip);

		if(SBData->conn.ip_family)
		{

			memset(&remote_addr_ip6, 0, sizeof(struct sockaddr_in6));
			remote_addr_ip6.sin6_family = h->h_addrtype;
			memcpy((char *) &remote_addr_ip6.sin6_addr.s6_addr, h->h_addr_list[0], h->h_length);
			remote_addr_ip6.sin6_port = htons(conn->port);
		}
		else
		{
			memset(&remote_addr, 0, sizeof(struct sockaddr_in));
			remote_addr.sin_family = h->h_addrtype;
			memcpy((char *) &remote_addr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
			remote_addr.sin_port = htons(conn->port);
		}

		if(-1 == connServer(socket, &remote_addr,&remote_addr_ip6,SBData->timeout, SBData))
		{
			free(newReq);
			CLOSE_SOCKET(socket);
			return -1;
		}

		TIZEN_LOGD("Connect Success in Watchdog");

		if (-1 == send(socket, newReq, length, 0))
		{
			TIZEN_LOGD("Watch Dog Thread got Exception during send [%s]", strerror (errno));
		}
		else
		{
			TIZEN_LOGD("Send HTTP Request Success in Watchdog");
			memset(recv_buf, 0, MAX_HEADERS_SIZE + 1);
			while (SBData->cthread->threadStatus != THREAD_FINISH)
			{

				int32 len = 0;
				int32 offset = 0;
				int32 rcvdLen = 0;
				int32 headerLen = 0;
				int retval = -1;

				if(watchdog_conn_poll(socket, SBData) <= 0)
				{
					TIZEN_LOGD("Error !!! watchdog thread pollfd failed Timeout or Fail or Exit");
					break;
				}

				rcvdLen = recv(socket, recv_buf + offset, MAX_HEADERS_SIZE - offset, 0);
				TIZEN_LOGD("Recvd lenght [%d]",rcvdLen);

				if (rcvdLen > 0)
				{
					TIZEN_D_LOGD("Watch1 Dog Thread Response [%s]",recv_buf);
					len = decode_http_find_str(recv_buf, END_OF_HEADERS);
					if (-1 != len)
					{

						headerLen = len + 4;
						TIZEN_LOGD("Watch Dog Thread Response [%s]",recv_buf);

						memset(&httprsp, 0, sizeof(httpResp));

						decode_http_rsp_init(recv_buf, headerLen, &httprsp);
						retval = process_http_rsp(&httprsp);

						if ((HTTP_RSP_REDIRECT  == retval) && (httprsp.location != NULL))
						{
							TIZEN_LOGD("Redirection Happening and New Location [%s]", httprsp.location);

							if(handleRedirection(httprsp.location, interface_index, &newReq, &length, SBData) == HTTP_RSP_DECODING_SUCCESS)
							{
								retval_watch_dog = 0;
								CLOSE_SOCKET(socket);
								socket = -1;
								break;
							}
							else
							{
								break;
							}
						}
						else if(HTTP_RSP_DECODING_SUCCESS != retval)
						{
							TIZEN_LOGD("HTTP Decoding Error");
							break;
						}

						TIZEN_LOGD("HTTP Response in Watch Dog is SUCCESS");
						contLength = atol(httprsp.contLen);

						if(httprsp.connection != NULL)
							connType = strncmp(httprsp.connection, "close", strlen("close"));

						if(connType != 0)
						{
							TIZEN_LOGD("Connection Type is Not CLOSE");
							connType = 1;
						}
						endTime = get_time_in_microsec();
						timeT2 = (endTime-startTime)/1000;

						resp_offset = offset + rcvdLen;
						resp_len = len + 4;
						TIZEN_LOGD("Response Lenght in Watch dog [%d] and Data Read till Now [%d]",resp_len, resp_offset);
						break;
					}
					offset = offset + rcvdLen;
					if(offset >= MAX_HEADERS_SIZE)
						break;
				}
				else
				{
					/* Socket error */
					break;
				}
			}
			delete_http_rsp(&httprsp);
			if(retval_watch_dog == 1)
				break;
		}
	}
	if(endTime == 0)
	{
		TIZEN_LOGD("End Time is Zero");
		/* Error condtion abort multisocket(This interface is not stable) */
		retval = -1;
	}
	else
	{
		/* Compair the time between two interfaces */
		retval = check_speed(SBData, timeT2, resp_offset, resp_len, recv_buf, socket, contLength);

		if(retval == 0)
		{
			retval = connType;
		}
	}

	CLOSE_SOCKET(socket);

	if((store_interface_ip_request(newReq, SBData, interface_index) == 0))
	{
		SBData->watch_dog_complete = 1;
	}

	free(newReq);

	TIZEN_LOGD("RETURN VALUE [%d]",retval);
	return retval;
}

int32 check_speed(SmartBondingData *SBData, uint32 timeT2, uint32 resp_offset,
										uint32 resp_len, int8 *recv_buf, int32 socket, uint64 contLength)
{
	int32 retval = 0;
	StatDetails *stat = &(SBData->stat);

	if(stat->timeT1 > (5 * timeT2))
	{
		/* Watch Dog Socket Becomes Main Socket */
		TIZEN_LOGD("Interface 2 Much Faster Than Interaface 1");
		//CLOSE_SOCKET(SBData->socket_fd);
		//SBData->socket_fd = 0;
		//retval = -1;
	}
	else if(timeT2 > (5 * stat->timeT1))
	{
		TIZEN_LOGD("IF 1 much faster than 2 abort \n");
		/* Abort multi socket */
		//retval = -1;
	}
	return retval;
}

int32 get_bytesof_range_request(uint64 *start, int8 *rangeHeader)
{
	int32 len = 0;
	int8 *i1 = NULL;
	int8 *i2 = NULL;
	int8 *i3 = NULL;
	int8 *i4 = NULL;
	int8 temp1[100] = {0};

	len = decode_http_find_str(rangeHeader, "bytes");
	if (len != -1)
	{
		i1 = strchr(rangeHeader, '=');
		i2 = strchr(rangeHeader, '-');
		i3 = strrchr(rangeHeader, '-');
		i4 = strchr(rangeHeader, ',');

		if ((i1 == 0) || (i2 == 0) || ((i1+1) >= i2) || (i2 != i3) || (i4!=0))
		{
			return B_FALSE;
		}
		else
		{
			strncpy(temp1, rangeHeader + 6, ((i2 -i1)-1));
			*start = atol(temp1);
			return B_TRUE;
		}
	}
	else
	{
		return B_FALSE;
	}
}

int32 is_connection_header_keepalive(SmartBondingData *SBData)
{
	if (SBData->resp.connection != NULL)
	{
		if (strcmp(SBData->resp.connection, "Keep-Alive") == 0)
			return 1;
	}
	return 0;
}

CThread * cthread_init()
{
	CThread *cthread = malloc(sizeof(CThread));
	if(cthread == NULL)
	{
		TIZEN_LOGD("Error !!! cthread allocation failed [%d] [%s]", errno, strerror(errno));
		return NULL;
	}
	memset(cthread,0,sizeof(CThread));
	cthread->threadId = 0;
	return cthread;
}

void cthread_start_thread(SmartBondingData *SBData)
{
	int32 ECode = 0;
	pthread_t thread = 0;
	CThread *cthread = SBData->cthread;
	TIZEN_D_LOGD("Starting Thread");
	if ((ECode = pthread_create(&thread, NULL, cthread_entry_function, (void *)SBData)) != 0)
	{
		TIZEN_LOGD("Error !!! creating pthread [%d] [%s]", errno, strerror(errno));
		cthread_exit(cthread);
	}
	else
	{
		TIZEN_D_LOGD("Init Watch Dog Thread ");
		cthread->threadStatus = THREAD_INIT;
		cthread->threadId = thread;
	}
}


void * cthread_entry_function (void *pArg)
{
	if(pArg)
	{
		SmartBondingData *SBData = (SmartBondingData *)pArg;
		if(SBData->twoChunk == 1)
			file_cthread_run_thread(SBData);
		else
			cthread_run_thread(SBData);
	}
	else
	{
		cthread_exit((CThread *)pArg);
	}
	return 0;
}

int32 cthread_get_thread_status(CThread *cthread)
{
	return cthread->threadStatus;
}

void cthread_exit(CThread *cthread)
{
	TIZEN_LOGD("Cthread Exit\n");
	if(cthread != NULL)
	{
		if(cthread->threadStatus == THREAD_INIT)
			usleep(100000);
		cthread->threadStatus = THREAD_FINISH;
		if(0 != cthread->threadId)
			pthread_join(cthread->threadId,NULL);
		cthread->threadId = 0;
		free(cthread);
		cthread = NULL;
	}
}

int32 get_req_without_range(int8 *oldReq, int8 *newReq, int8 *rangeHeader, uint64 *rangeStart)
{
	int32 len = 0;
	int32 tempLen = 0;
	int8 *temp = NULL;

	if (get_bytesof_range_request(rangeStart, rangeHeader))
	{
		len = decode_http_find_str(oldReq, RANGELEN_REQ_HEADER_CMP1);
		if(len == -1)
			len = decode_http_find_str(oldReq, RANGELEN_REQ_HEADER_CMP2);
		tempLen = len;
		memcpy(newReq, oldReq, len);
		TIZEN_LOGD ("Before Range [%s] Range Header [%s]", newReq, rangeHeader);
		temp = oldReq + len;
		if(!(decode_http_find_str(temp, END_OF_LINE) == decode_http_find_str(temp, END_OF_HEADERS)))
		{
			/*this will bring to point after Rnage header*/
			len = decode_http_find_str(temp, END_OF_LINE);
			temp = temp + len + 2;
		}
		else
		{
			len = decode_http_find_str(temp, END_OF_HEADERS);
			temp = temp + len + 2;
		}
		memcpy(newReq + tempLen, temp, strlen(temp));
		TIZEN_LOGD ("Successfully removed range header [%s]", newReq);
		return strlen(newReq);
	}
	else
	{
		free(newReq);
		newReq = NULL;
		return 0;
	}
}


#ifdef TIZEN_UX_SUPPORT
static void _smart_bonding_start_cb(smbd_event_info_t event, void *user_data)
{
	TIZEN_LOGD("start bonding cb \n");
	SmartBondingData *SBData = (SmartBondingData *)user_data;
	switch (event.Event) {
	case SMBD_EVENT_USER_OPTION_OK:
		if(SBData != NULL)
			SBData->user_option = USER_OK;
		break;
	case SMBD_EVENT_USER_OPTION_CANCEL:
		if(SBData != NULL)
			SBData->user_option = USER_CANCEL;
		break;
	default:
		break;
	}
}

int32 user_selection(SmartBondingData *SBData)
{
	int32 retval = B_FALSE;
	int status = VCONFKEY_NETWORK_CELLULAR_NO_SERVICE;
	CThread *cthread = SBData->cthread;
	TIZEN_LOGD("Test For Tizen Ux Support");
	if(!(smartbonding_client_init()))
		return retval;

	TIZEN_LOGD("INIT UX Library User Option");

	while(SBData->response_check == 0 && cthread->threadStatus != THREAD_FINISH)
	{
		if(cthread->threadStatus != THREAD_FINISH)
			usleep(10000);
		else
			return retval;
	}

	vconf_get_int(VCONFKEY_NETWORK_CELLULAR_STATE, &status);

	TIZEN_LOGD("current LTE status [%d] and Expected LTE Status [%d]", status, VCONFKEY_NETWORK_CELLULAR_ON);

	while(((status) != VCONFKEY_NETWORK_CELLULAR_ON) && (cthread->threadStatus != THREAD_FINISH))
	{
		TIZEN_D_LOGD("LTE Data pack Off");
		usleep(100000);
		status = VCONFKEY_NETWORK_CELLULAR_NO_SERVICE;
		vconf_get_int(VCONFKEY_NETWORK_CELLULAR_STATE, &status);
	}

	TIZEN_LOGD("Data Pack On status [%d]", status);

	if (smart_bonding_start(SBData->req.url, SBData->resp.cLen, _smart_bonding_start_cb, (void *)SBData) !=  SMBD_ERR_NONE)
	{
		TIZEN_LOGD("Start Bonding API failed");
		return retval;
	}

	TIZEN_LOGD("Start Bonding API success");
	SBData->user_option = USER_POP_UP;

	while(SBData->user_option == USER_POP_UP && cthread->threadStatus != THREAD_FINISH)
	{
		if(cthread->threadStatus != THREAD_FINISH)
			usleep(10000);
		else
			return retval;
	}

	if(SBData->user_option != USER_OK)
	{
		TIZEN_LOGD("User selected cancel");
		return retval;
	}

	retval  = B_TRUE;
	TIZEN_LOGD("User selected OK");
	return retval;
}
#endif

void file_cthread_run_thread(SmartBondingData *SBData)
{
	uint32 bIsUp = 0;
	uint32 bFileStreamStarted = 0;
	uint64 speed_time = get_time_in_sec();
	connection *conn = &(SBData->conn);
	CThread *cthread = SBData->cthread;
	cthread->threadStatus = THREAD_RUNNING;
	float ratio =  0; /* Ratio of Wifi/LTE speed */
	uint32 wifiSpeed = 0;
	uint32 lteSpeed = 0;
	uint64 expected_bytes = 0;
	FILE *fp = NULL;

	if(SBData->interface_index == 1)
	{
		TIZEN_LOGD("Main Interface is LTE");
		return;
	}

#ifdef TIZEN_UX_SUPPORT
	if(!user_selection(SBData))
		return;
#endif

	fp= fopen("/opt/usr/media/Ratiostat", "r");

	if (fp != NULL)
	{
		int32 nitems = 0;
		nitems = fscanf (fp, "%u %u",&lteSpeed,&wifiSpeed);
		nitems = nitems;
		TIZEN_LOGD("LTE SPEEED IS [%u] and WIFI SPEED IS [%u]",lteSpeed,wifiSpeed);
		if( (lteSpeed != 0) && ( wifiSpeed != 0))
		{
			ratio = (double)lteSpeed/(double)wifiSpeed;
		}
		TIZEN_LOGD("Ratio of Previous Download From History %f", ratio);
	}
	else
	{
		TIZEN_LOGD("Failed to Open History previous Download");
	}

	while ((cthread->threadStatus != THREAD_FINISH) && ((SBData->resp.cLen - SBData->response_body_read) > (MULTIRAT_LOWER_LIMIT_TWO_CHUNK * 2)))
	{
		if(ratio > 0)
		{
			ratio = MAX(0.1, MIN(10,ratio));
			expected_bytes = ((SBData->resp.cLen - SBData->response_body_read)/(ratio + 1));
		}
		else
			expected_bytes  = (SBData->resp.cLen - SBData->response_body_read)/2;

		expected_bytes += SBData->response_body_read;

		bIsUp = is_both_interface_avail(conn->ifaceInfo,conn->ip_family);
		if (bIsUp)
		{
			SBData->expectedbytes  = expected_bytes;
			TIZEN_LOGD("Expected Bytes [%llu]", SBData->expectedbytes);

			file_stream_init(SBData);

			if((bFileStreamStarted = file_stream_start(SBData)))
			{
				SBData->fileThreadStarted = bFileStreamStarted;
				TIZEN_LOGD("File Stream Started [%d]",bFileStreamStarted);
				break;
			}
		}
		usleep(10000);
	}

	if(!(SBData->fileThreadStarted))
		return;

	while (cthread->threadStatus != THREAD_FINISH)
	{
		uint32 status = 0;

		status = speed_calc_check_compare(&speed_time, SBData);

		if(!status)
			break;

		usleep(20000);
	}

	cthread->threadStatus = THREAD_FINISH;
	return ;
}

void cthread_run_thread(SmartBondingData *SBData)
{
	uint32 bIsUp = 0;
	uint32 chunk_div = 0;
	uint32 min_chunk = 0;
	uint32 max_chunk = 0;
	uint32 bMultiSocketStarted = 0;
	uint64 bytesForMultiSocket = 0;
	int32 conn_type = 0;
	connection *conn = &(SBData->conn);
	MultiSockInput mSockInput;
	CThread *cthread = SBData->cthread;
	cthread->threadStatus = THREAD_RUNNING;
	/* NOT USED FOR 2 chunk approach */

	if(SBData->interface_index == 1)
	{
		TIZEN_LOGD("Main Interface is LTE");
		return;
	}

#ifdef TIZEN_UX_SUPPORT
	if(!user_selection(SBData))
		return;
#endif

	bytesForMultiSocket = SBData->resp.cLen - SBData->response_body_read;

	while ((cthread->threadStatus != THREAD_FINISH) && (bytesForMultiSocket > MULTIRAT_LOWER_LIMIT))
	{
		bIsUp = is_both_interface_avail(conn->ifaceInfo,conn->ip_family);
		if (bIsUp)
		{
			memset(&mSockInput, 0, sizeof(mSockInput));

			conn_type = watchdog_test_connection_type(SBData);
			if(conn_type == 1)
			{
				chunk_div = MULTIRAT_BLOCK_DIV;
				max_chunk = MAX_MULTIRAT_BLOCK_SIZE;
			}
			else if(conn_type == 0)
			{
				chunk_div = 2;
				max_chunk = MULTIRAT_CHUNK_SIZE;
			}
			else
			{
				TIZEN_LOGD("Aborting watch dog");
				break;
			}

			while(SBData->response_check == 0)
			{
				if(cthread->threadStatus != THREAD_FINISH)
					usleep(10000);
				else
					break;
			}

			min_chunk = MIN_MULTIRAT_BLOCK_SIZE;

			mSockInput.rspOffset = SBData->response_body_read + EXPECTED_BYTE;
			bytesForMultiSocket = SBData->resp.cLen - mSockInput.rspOffset;
			mSockInput.chunkSize = bytesForMultiSocket/chunk_div;
			mSockInput.conn = conn;

			if (mSockInput.chunkSize > max_chunk)
				mSockInput.chunkSize = max_chunk;
			else if (mSockInput.chunkSize < min_chunk)
				mSockInput.chunkSize =  min_chunk;


			if(bytesForMultiSocket > (mSockInput.chunkSize))
			{
				multirat_watchdogthread_calnochunks(mSockInput.chunkSize,
						&mSockInput.noOfChunks, &mSockInput.lastChunk, bytesForMultiSocket);
			}
			else
			{
				TIZEN_LOGD("Size too small ignoring this content");
				break;
			}

			TIZEN_LOGD("No of Chunks = [%d],Chunk Size = [%d] bytesForMultiSocket = [%llu]",
					mSockInput.noOfChunks, mSockInput.chunkSize, bytesForMultiSocket);

			multisocket_init(&mSockInput, SBData);
			if ((bMultiSocketStarted = multisocket_start(SBData)))
			{
				TIZEN_LOGD ("MultiSocket  started [%d]", bMultiSocketStarted);
				SBData->totalExpectedBytes = SBData->msocket->rspOffset;
				SBData->multiSocketThreadStarted = bMultiSocketStarted;
				break;
			}
			else
			{
				TIZEN_LOGD ("MultiSocket  failed");
				multisocket_exit(SBData->msocket);
				SBData->msocket = NULL;
				break;
			}
		}
		usleep(SLEEP_TIME);
		if(SBData->response_check !=0)
			bytesForMultiSocket = SBData->resp.cLen - SBData->response_body_read;
	}
	cthread->threadStatus = THREAD_FINISH;
	return ;
}

void multirat_watchdogthread_calnochunks(uint32 chunkSize, uint32 *noOfChunks, uint32 *lastChunk, uint64 totalSize)
{
	uint32 min = 0;
	uint32 tempChunk = 0;
	uint32 tempTotalChunks = 0;

	TIZEN_LOGD("Multirat Watchdog Thread CalNoChunks");

	tempChunk = (totalSize % chunkSize);
	min = MIN((chunkSize/3), MIN_LAST_CHUNK);
	if((0 != tempChunk) && (tempChunk < min))
	{
		tempTotalChunks = (totalSize/chunkSize);
		tempChunk = chunkSize + tempChunk;
		TIZEN_LOGD("Last Chunk Size Changed");
	}
	else
	{
		TIZEN_LOGD("Last Chunk Size not Chnaged");
		if(0 == tempChunk)
		{
			tempTotalChunks = (totalSize/chunkSize);
		}
		else
		{
			tempTotalChunks = (totalSize/chunkSize) + 1;
		}
		tempChunk = 0;
	}
	*lastChunk = tempChunk;
	*noOfChunks = tempTotalChunks;
}

