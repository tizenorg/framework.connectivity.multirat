#include "multirat_conf.h"
#include "multirat_process.h"
#include "multirat_watch_dog_thread.h"
#include "multirat_multisocket.h"
#include "multirat_libapi.h"
#include "multirat_watchthread.h"
#include "multirat_poll_thread.h"
#ifdef TIZEN_UX_SUPPORT
#include "smartbonding-client.h"
#endif
#include "multirat_file_stream.h"
#include <glib.h>
#include <dbus/dbus.h>
#include <ares.h>
#include <wifi.h>
#include <net_connection.h>
#include <vconf.h>
#include <vconf-keys.h>

#define _E(fmt, args...)   SLOGE(fmt, ##args)

#define BUS_NAME               "org.tizen.system.deviced"
#define PATH_NAME              "/Org/Tizen/System/DeviceD/Process"
#define INTERFACE_NAME         "org.tizen.system.deviced.Process"
#define METHOD_NAME            "GetSiopLevel"

#define DEVICED_DBUS_TIMEOUT   (120 * 1000)

#define VCONF_SMART_BONDING_POLICY "file/private/wifi/network_bonding"
#define SMART_BONDING_WIFI_ONLY 0x00

#define DNS_NUM 2

static void state_cb(void *data, int s, int read, int write)
{
	TIZEN_D_LOGD("Change state fd [%d] read:[%d] write:[%d]", s, read, write);
}


static void callback(void *arg, int status, int timeouts, struct hostent *host)
{
	TIZEN_D_LOGD("Call Back");
	SmartBondingData *SBData = (SmartBondingData *)arg;
	connection *conn = &(SBData->conn);
	if(!host || status != ARES_SUCCESS)
	{
		TIZEN_LOGD("Failed to lookup [%s]", ares_strerror(status));
		return;
	}

	TIZEN_D_LOGD("Found address name [%s]", host->h_name);

	char ip[INET_ADDRSTRLENG];

	inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, sizeof(ip));
	SBData->dns = 1;
	memset(conn->ifaceInfo[SBData->dns_iface].server_ip, 0, INET_ADDRSTRLENG);
	memcpy(conn->ifaceInfo[SBData->dns_iface].server_ip, ip, INET_ADDRSTRLENG);
}

static void wait_ares(ares_channel channel, SmartBondingData *SBData)
{
	fileStream *fStream = SBData->fStream;
	while(fStream->compRspRcvdFlag)
	{
		struct timeval *tvp, tv;
		fd_set read_fds, write_fds;
		int nfds;
		int select_return = 0;

		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		TIZEN_D_LOGD("Before Select Ares Wait");
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if(nfds == 0)
		{
			break;
		}
		tv.tv_sec = 0; tv.tv_usec = 500000;
		tvp = ares_timeout(channel, &tv, &tv);
		select_return = select(nfds, &read_fds, &write_fds, NULL, tvp);
		if(select_return == -1)
		{
			TIZEN_LOGD("Select Failed");
			break;
		}
		else if(select_return == 0)
		{
			TIZEN_D_LOGD("Time out in Select Ares DNS Call");
			continue;
		}
		else
		{
			TIZEN_D_LOGD("After Select Ares Wait");
			ares_process(channel, &read_fds, &write_fds);
		}
	}
}


static DBusMessage *method_call(const char *dest, const char *path,
const char *interface, const char *method);

void get_object_size(httpResp *resp)
{
	int32 len = 0;

	len = decode_http_find_str(resp->contRange, "/");
	if (len != -1)
	{
		len=len + 1;
		resp->instanceSize = atol(resp->contRange + len);
		return;
	}
	else
	{
		resp->instanceSize = 0;
	}
	return;
}

void store_check_http_response(SmartBondingData *SBData)
{
	httpResp *resp = &(SBData->resp);

	/*For filling request structure members */
	if (HTTP_RSP_DECODING_SUCCESS != process_http_rsp(resp))
	{
		TIZEN_LOGD("Error !!! decoding response failed");
		delete_http_rsp(resp);
		return;
	}

	/*
	 *response_body_read gets incrementd when data is read_from_network.
	 *We need to subtract headers from this to get the actual body lenght
	 */
	if (resp->contRange != NULL)
	{
		get_object_size(resp);
	}

	if (SBData->multiRatCheckDone != B_TRUE)
	{
		TIZEN_D_LOGD("about to enable multirat");
		SBData->enableMultiRat = should_enable_multirat(SBData);
		if ((SBData->enableMultiRat) && (NULL == SBData->cthread) && (!SBData->bRafMode))
		{
			TIZEN_LOGD("MultiRAT is enabled as content length [%llu] body read so far [%llu]",
					resp->cLen, SBData->response_body_read);
			/*watchdog cthread is being created */
			SBData->cthread = cthread_init();
			/*  watchdog cthread is initialised */
			cthread_start_thread(SBData);
			TIZEN_D_LOGD ("MultiRat enabled, waiting for to start multi socket");
		}
		SECURE_DB_INFO("Response [%s]", resp->resp_buff);
		TIZEN_LOGD("Enable MultiRat ?? [%d]", SBData->enableMultiRat);
		SBData->multiRatCheckDone = B_TRUE;
	}
}

void store_http_request(int8 *req, SmartBondingData *SBData)
{
	int32 len = 0;
	httpReq *dupReq = &(SBData->req);

	len = decode_http_find_str(req, "\r\n\r\n");

	if (len != -1)
	{
		len = len + 5;

		dupReq->req_buff = (int8 *)malloc(len);
		if(dupReq->req_buff == NULL)
		{
			TIZEN_LOGD("Error !!! SBData->req->req_buff allocation failed [%d] [%s]", errno, strerror(errno));
			return;
		}
		memset(dupReq->req_buff, 0, len);
		memcpy(dupReq->req_buff, req, len-1);
		dupReq->reqLen = len-1;

		TIZEN_D_LOGD("HTTP request is [%s]", dupReq->req_buff);

		if (HTTP_RSP_DECODING_SUCCESS != decode_http_req(dupReq))
		{
			TIZEN_LOGD("Error !!! HTTP req decode is failed ");
			delete_http_req(dupReq);
			return;
		}

		if (dupReq->Rangeheader != NULL)
		{
			dupReq->req_buff_wo_range = (int8 *)malloc(len);
			if(NULL != dupReq->req_buff_wo_range)
			{
				memset(dupReq->req_buff_wo_range, 0, len);
				dupReq->req_wo_len = get_req_without_range(dupReq->req_buff,
						dupReq->req_buff_wo_range, dupReq->Rangeheader, &dupReq->rangeStart);
				SBData->startOffset = (dupReq->rangeStart);
			}
		}
	}
	return;
}

uint32 should_enable_multirat(SmartBondingData *SBData)
{
	uint32 method_get = 0;
	uint32 bUseMultiRat = 0;
	httpReq *req = &(SBData->req);
	httpResp *resp = &(SBData->resp);
	int32 smartbonding_value = 0;

	TIZEN_LOGD("multirat process should_enable_multirat Threshold [%d]",get_multirat_threshold());

	vconf_get_int(VCONF_SMART_BONDING_POLICY, &smartbonding_value);

	if (smartbonding_value == SMART_BONDING_WIFI_ONLY)
	{
		TIZEN_LOGD("Smart bonding policy is OFF");
	}

	if (req->method == HTTP_GET) {
		TIZEN_D_LOGD("HTTP method is GET");
		method_get = 1;
	}

	if (resp->rspcode != NULL && resp->contLen != NULL)
	{
		SBData->content_length = resp->cLen;

		bUseMultiRat = ((method_get)  &&
				(!(strncasecmp(resp->rspcode,"200",3))  ||
						!(strncasecmp(resp->rspcode , "206",
								3))) && (resp->acceptFlag) &&
								(resp->cLen > get_multirat_threshold()) && (!SBData->interface_index) && (smartbonding_value));
		SBData->multiRatCheckDone = B_TRUE;
	}
	if(bUseMultiRat)
	{
		return !(getTempLevel(SBData));
	}

	TIZEN_D_LOGD("can we start MultiRat? [%d]", bUseMultiRat);
	return bUseMultiRat;
}

void start_watchdog(SmartBondingData *SBData, int8 *buffer, int32 my_nread)
{
	int32 len = 0;
	uint32 length_check = 0;
	uint32 write_len = 0;
	uint64 endTime = 0;
	httpResp *resp = &(SBData->resp);
	StatDetails *stat = &(SBData->stat);

	TIZEN_D_LOGD("checking for response response_check_length[%d] my_nread[%d]", SBData->response_check_length, my_nread);
	length_check = SBData->response_check_length + my_nread;

	if(length_check > (MAX_HEADER_SIZE - DIRECT_WRITE_HEADER_LENGTH))
		length_check = (MAX_HEADER_SIZE - DIRECT_WRITE_HEADER_LENGTH) - SBData->response_check_length;
	else
		length_check = my_nread;

	memcpy(resp->resp_buff + SBData->response_check_length, buffer, length_check);
	SBData->response_check_length = SBData->response_check_length + my_nread;
	TIZEN_LOGD("checking for response response_check_length[%d] my_nread[%d]", SBData->response_check_length, my_nread);
	len = decode_http_find_str(resp->resp_buff,END_OF_HEADER);

	if (len != -1)
	{
		len = len + 4;
		TIZEN_LOGD("Response Header Length [%d]", len);

		endTime = get_time_in_microsec();
		stat->dataStrtTime = endTime;
		stat->dataOffsetTime = endTime;

		resp->resp_header_length = len;
		write_len = (SBData->response_check_length > (MAX_HEADER_SIZE - DIRECT_WRITE_HEADER_LENGTH)) ? (MAX_HEADER_SIZE - DIRECT_WRITE_HEADER_LENGTH): SBData->response_check_length;
		memcpy(resp->resp_buff_body, resp->resp_buff, write_len);
		memset((resp->resp_buff+len),0,MAX_HEADER_SIZE-len);
		store_check_http_response(SBData);
		SBData->response_body_read = SBData->response_body_read - len;
		stat->timeT1 = (endTime - stat->startTime)/1000;
		SBData->response_check = 1;
	}
	else
	{
		if(SBData->response_check_length > (MAX_HEADER_SIZE - DIRECT_WRITE_HEADER_LENGTH))
		{
			SBData->response_check = 1;
			TIZEN_LOGD("Invalid Header Not passing through SB");
		}
	}
}

int8 *get_new_req(int8 *req, uint64 rangeStart, uint64 bytesRead, uint64 rangeEnd, uint32 *length, uint32 len, int32 proxy)
{
	int32 rangeLen = 0;
	int8 *newRequest = NULL;
	int8 rangeField[MAX_RANGE_FIELD_LEN] = { 0 };

	newRequest = (int8*)malloc(len + MAX_RANGE_FIELD_LEN);

	if (newRequest == NULL)
	{
		TIZEN_LOGD("NewRequest allocation failed\n");
		return NULL;
	}
	memset(newRequest, 0, len + MAX_RANGE_FIELD_LEN);

	if (rangeEnd)
	{
		rangeLen = sprintf(rangeField, "%s%llu%s%llu%s", "Range: bytes=", rangeStart + bytesRead, "-", rangeEnd, "\r\n\r\n");
	}
	else
	{
		rangeLen = sprintf(rangeField, "%s%llu%s%s", "Range: bytes=", rangeStart + bytesRead, "-", "\r\n\r\n");
	}

	TIZEN_LOGD("RebuildReq rangeLen %d", rangeLen);
	SECURE_DB_INFO("Req without change %s\n", req);

	int32 offset = 0;

	if (proxy)
	{
		if (0 != strncmp(req + 4, "http://", 7))
		{
			/* Request is of type GET /lkkk.gif  */
			char *hostName = NULL;
			getHost(&hostName, req);
			if (NULL != hostName)
			{
				char reqLine[20] = { 0 };
				strcpy(reqLine, "GET http://");

				if (req[4] != '/')
				{
					offset = sprintf(newRequest, "%s%s%s", reqLine, hostName, "/");
				}/* End of if */
				else
				{
					offset = sprintf(newRequest, "%s%s", reqLine, hostName);
				}/* End of else */
				TIZEN_LOGD("Proxy offset %d\n", offset);
			}/* End of if */
			else
			{
				SECURE_DB_INFO("Invalid relative request without host name, %s", req);
			}
			SECURE_DB_INFO("Proxy Rereq without range [%s]", newRequest);
			memcpy(newRequest + offset, req + 4, len - 6);
			offset = offset + len - 6;
			SECURE_DB_INFO("Proxy RebuildReq without range [%s]", newRequest);
		}
		else
		{
			memcpy(newRequest, req, len - 2);
			offset = len - 2;
		}
	}/* End of if */
	else
	{
		int http_len = strlen("http://");
		if (0 == strncmp(req + 4, "http://", http_len))
		{
			/* Destination Interface not proxied and request is absolute*/
			char *pHost = req + 4 + http_len; /* Move past GET http:// */
			char *pUrl = strchr(pHost, '/');
			if (NULL == pUrl)
			{
				SECURE_DB_INFO("pUrl null phost [%s]", pHost);
				pUrl = pHost; /* Just to avoid crash as null return of newRequest is not handled*/
			}

			memcpy(newRequest, req, 4);
			memcpy(newRequest + 4, pUrl, len - ((pUrl - req) + 2)); /* Copy whole url except \r\n*/
			offset = 4 + len - ((pUrl - req) + 2);
		}
		else
		{
			memcpy(newRequest, req, len);
			offset = len - 2;
		}
	}
	SECURE_DB_INFO("RebuildReq without range [%s]", newRequest);
	memcpy(newRequest + offset, rangeField, rangeLen);
	*length = offset + rangeLen;
	newRequest[*length] = '\0';
	return newRequest;
}
int32 send_req(int8 *req, uint32 reqLen,int32 socket,uint32 index, SmartBondingData *SBData)
{
	int32 retval = 0;
	uint32 timeout = SBData->timeout;
	int8 temp[1] = {0};
	struct hostent *h = NULL;
	struct sockaddr_in remote_addr;
	struct sockaddr_in6 remote_addr_ip6;
	connection *conn = &(SBData->conn);

	if(SBData->watch_dog_complete == 1)
		h = gethostbyname(conn->ifaceInfo[index].server_ip);
	else
		h = gethostbyname(conn->ip_addr);

	if(SBData->conn.ip_family)
	{
		memset(&remote_addr_ip6, 0, sizeof(struct sockaddr_in6));
		remote_addr_ip6.sin6_family = h->h_addrtype;
		memcpy((int8 *) &remote_addr_ip6.sin6_addr.s6_addr, h->h_addr_list[0], h->h_length);
		remote_addr_ip6.sin6_port = htons(conn->port);

	}
	else
	{
		memset(&remote_addr, 0, sizeof(struct sockaddr_in));
		remote_addr.sin_family = h->h_addrtype;
		memcpy((int8 *) &remote_addr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
		remote_addr.sin_port = htons(conn->port);
	}

	if(-1 == connServer(socket, &remote_addr, &remote_addr_ip6,(timeout/2),SBData))
	{
		TIZEN_LOGD("connection is Failed");
		return 0;
	}
	else
	{
		TIZEN_LOGD("connection is done successfully");
	}

	if (-1 == send(socket, req, reqLen, 0))
	{
		TIZEN_LOGD("Main Socket Exception got Exception during send [%s]", strerror (errno));
	}
	else
	{
		TIZEN_LOGD("Main Socket Exception Send HTTP Request Success");
		retval = read_conn_poll(socket, SBData);
		if(retval == -1)
		{
			TIZEN_LOGD("Main Socket Exception Data Poll Error");
			retval = 0;
		}
		else if(retval == 0)
		{
			TIZEN_LOGD("Main Socket Exception Data Poll Timeout");
		}
		else
		{
			retval = recv(socket, temp, 1, MSG_PEEK);
			if(retval < 0)
				retval = 0;
		}
	}

	TIZEN_LOGD("RETURN VALUE IN MAIN SOCKET EXPCETION [%d]",retval);
	return retval;
}

void smart_bonding_exit(SmartBondingData *SBData)
{
	int32 nbytes = 0;
	if(SBData != NULL)
	{
		TIZEN_LOGD("SBData[%p] smart_bonding_exit", SBData);
		if (SBData->socket_fd > 0)
		{
			CLOSE_SOCKET(SBData->socket_fd);
			SBData->socket_fd = -1;
		}

		if(SBData->PollThrd != NULL)
		{
			if(SBData->PollThrd->threadStatus == THREAD_INIT)
				usleep(100000);

			SBData->PollThrd->threadStatus = THREAD_FINISH;
			TIZEN_D_LOGD("Write Data to Noti Pipe Fd [%s]", NOTI_TRIGGER);
			nbytes = write(SBData->noti_pipefd[1], NOTI_TRIGGER, NOTI_TRIGGER_LENGTH);
			nbytes = nbytes; /*Warning remove */
			PollThread_exit(SBData->PollThrd);
			SBData->PollThrd =  NULL;
		}

		TIZEN_LOGD("Poll thread Closed Successfully");

		if(SBData->cthread != NULL)
		{
			TIZEN_LOGD("sb_exit watchdog thread [%p]", SBData->cthread);
			cthread_exit(SBData->cthread);
			SBData->cthread =  NULL;
		}

		if(SBData->curlThrd != NULL)
		{
			TIZEN_LOGD("sb_exit curlThrd thread [%p]", SBData->curlThrd);
			curlThread_exit(SBData->curlThrd);
			SBData->curlThrd =  NULL;
		}

		if(SBData->msocket != NULL)
		{
			TIZEN_LOGD("sb_exit SBData_msocket [%p]", SBData->msocket);
			multisocket_exit(SBData->msocket);
			TIZEN_LOGD("Multisocket freed");
			SBData->msocket = NULL;
		}

		if(SBData->fStream != NULL)
		{
			file_stream_exit(SBData->fStream);
			TIZEN_LOGD("File Stream Exit");
			SBData->fStream = NULL;
		}

		delete_http_req(&(SBData->req));

		delete_http_rsp(&(SBData->resp));

#ifdef TIZEN_UX_SUPPORT
		if(lib_init_success() == 1)
		{
			if(SBData->user_option != 0)
			{
				TIZEN_LOGD("Remove POP UP");
				smart_bonding_stop((void *)SBData);
			}
		}
#endif

		pthread_mutex_destroy(&SBData->tempLock);
		if(SBData->raFileMngr.writeFD1 != NULL)
		{
			fclose(SBData->raFileMngr.writeFD1);
			SBData->raFileMngr.writeFD1 = NULL;
		}
		if(SBData->raFileMngr.writeFD2 !=NULL)
		{
			fclose(SBData->raFileMngr.writeFD2);
			SBData->raFileMngr.writeFD2 = NULL;
		}

		CLOSE_SOCKET(SBData->noti_pipefd[0]);
		CLOSE_SOCKET(SBData->noti_pipefd[1]);
		CLOSE_SOCKET(SBData->trigger_pipefd[0]);
		CLOSE_SOCKET(SBData->trigger_pipefd[1]);

		TIZEN_LOGD("All PIPE/File FD are close");

		free(SBData);
		SBData = NULL;
		TIZEN_LOGD("Multisocket Exit new sb_exit finished");
	}
	else
	{
		TIZEN_LOGD("SBdata null sb_exit finished");
	}
}

static DBusMessage *method_call(const char *dest, const char *path,
const char *interface, const char *method)
{
	DBusMessageIter iter;
	DBusError err;
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusConnection *conn = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn)
	{
		_E("dbus_bus_get error");
		return NULL;
	}

	msg = dbus_message_new_method_call(dest, path, interface, method);
	if (!msg) {
		_E("dbus_message_new_method_call(%s:%s-%s)", path, interface, method);
		return NULL;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg,
			DEVICED_DBUS_TIMEOUT, &err);
	if (!reply)
	{
		_E("dbus_connection_send error(No reply)");
	}

	if (dbus_error_is_set(&err))
	{
		_E("dbus_connection_send error(%s:%s)", err.name, err.message);
		dbus_error_free(&err);
		reply = NULL;
	}

	dbus_message_unref(msg);
	return reply;
}

int get_siop_level(void)
{
	DBusError err;
	DBusMessage *msg;
	int32 ret, level;

	msg = method_call(BUS_NAME, PATH_NAME, INTERFACE_NAME, METHOD_NAME);
	if (!msg)
		return -1;

	dbus_error_init(&err);

	ret = dbus_message_get_args(msg, &err, DBUS_TYPE_INT32, &level,
			DBUS_TYPE_INVALID);
	if (!ret) {
		_E("no message : [%s:%s]", err.name, err.message);
		level = -1;
	}
	dbus_message_unref(msg);
	dbus_error_free(&err);

	return level;
}

int32 getTempLevel(SmartBondingData *SBData)
{
#if 0
	int32 level = 0;
	TIZEN_LOGD("Get Temperature");
	pthread_mutex_lock(&SBData->tempLock);
	level = get_siop_level();
	pthread_mutex_unlock(&SBData->tempLock);
	TIZEN_LOGD("Temperature Level is %d",level);
	if(level == -1)
	{
		TIZEN_LOGD("Temperature Not Fetched Properly");
	}
	else if(level > get_multirat_temp_threshold())
	{
		TIZEN_LOGD("Temperature Is above threshold");
		return B_TRUE;
	}
#endif
	return B_FALSE;
}

uint64 get_time_in_microsec()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((tv.tv_sec * 1000000) + tv.tv_usec);
}

uint64 get_time_in_sec()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

void reset_stats(StatDetails *stat)
{
	stat->dataStrtTime = get_time_in_microsec();
	stat->dataOffsetTime = stat->dataStrtTime;
	stat->offsetForSpeed = 0;
	stat->dataOffset = 0;
	stat->mainSockSpeed = 0;
	memset(stat->dataArr,0,(100*sizeof(uint32)));
	memset(stat->timeArr,0,(100*sizeof(uint64)));
	stat->speedIndex = 0;
}

void getHost(char **host, char *reqHeaders)
{
	int len = 0;
	char *tempBuff = reqHeaders;

	len = decode_http_find_str(tempBuff,"\r\n");
	if(len == -1)
	{
		return;
	}/* End of if */
	tempBuff = tempBuff+len+2;
	while(strlen(tempBuff) > 0)
	{
		len = decode_http_find_str(tempBuff,"\r\n");
		if(len != 1)
		{
			if(0 == strncasecmp(tempBuff,"Host:",5))
			{
				*host = (char*)malloc(len + 1);
				memset(*host,0,len + 1);
				memcpy(*host,tempBuff+6,len-6);
				break;
			}/* End of if */
			tempBuff = tempBuff + len + 2;
		}/* End of if */
		else
		{
			break;
		}/* End of else */
	}/* End of while */
	return;
}/*  */

uint32 get_wifi_dns_ip(int8 *dns_ip)
{
	int32 ret = WIFI_ERROR_NONE;
	int8 *dns_ip_temp = NULL;
	wifi_ap_h ap_h;
	ret = wifi_initialize();
	if(ret != WIFI_ERROR_NONE)
		return B_FALSE;
	ret = wifi_get_connected_ap(&ap_h);
	if(ret != WIFI_ERROR_NONE)
		return B_FALSE;
	wifi_ap_get_dns_address(ap_h, 1, WIFI_ADDRESS_FAMILY_IPV4, &dns_ip_temp);
	SECURE_DB_INFO("WiFi DNS Server IP [%s]", dns_ip);
	memcpy(dns_ip, dns_ip_temp, strlen(dns_ip_temp));
	free(dns_ip_temp);
	return B_TRUE;
}

uint32 get_lte_dns_ip(int8 *dns_ip)
{
	int32 ret = CONNECTION_ERROR_NONE;
	int8 *dns_ip_temp = NULL;
	int32 service_type;
	connection_profile_h profile = NULL;
	connection_h connection = NULL;
	ret = connection_create(&connection);
	if(ret != CONNECTION_ERROR_NONE)
		return B_FALSE;
	service_type = CONNECTION_CELLULAR_SERVICE_TYPE_INTERNET;
	ret = connection_get_default_cellular_service_profile(connection, service_type, &profile);
	if(ret != CONNECTION_ERROR_NONE)
		return B_FALSE;
	connection_profile_get_dns_address(profile, 1, CONNECTION_ADDRESS_FAMILY_IPV4, &dns_ip_temp);
	SECURE_DB_INFO("LTE DNS Server IP [%s]", dns_ip_temp);
	memcpy(dns_ip, dns_ip_temp, strlen(dns_ip_temp));
	free(dns_ip_temp);
	return B_TRUE;
}

int getDNSInfo(char *host, int iface, SmartBondingData *SBData)
{
	int retval = 0;
	int8 *server_ip = NULL;
	int8 *interface_ip = SBData->conn.ifaceInfo[iface].ip;
	ares_channel channel;
	int status;
	connection *conn = &(SBData->conn);
	struct ares_options options;
	int optmask = 0;
	struct in_addr a4;
	uint32 ret = B_FALSE;
	char dns_ip[INET_ADDRSTRLENG] = {0};
	int i = 0;
	memset(dns_ip, 0 ,INET_ADDRSTRLENG);

	for(i = 1; i <= DNS_NUM; i++)
	{
		retval = 0;
		if(i == 1)
		{
			if(strcmp(conn->ifaceInfo[iface].dns_1, "") == 0)
			{
				TIZEN_LOGD("SBData[%p] First DNS IP Not Present", SBData);
				continue;
			}
			else
				strncpy(dns_ip, conn->ifaceInfo[iface].dns_1, strlen(conn->ifaceInfo[iface].dns_1));
		}
		else
		{
			if(strcmp(conn->ifaceInfo[iface].dns_2, "") == 0)
			{
				TIZEN_LOGD("No DNS IP from LTE Profile");
				ret = get_lte_dns_ip(dns_ip);
				if(ret!= B_TRUE)
				{
					TIZEN_LOGD("SBData[%p] Unable to fetch DNS Server IP", SBData);
					return retval;
				}
			}
			else
				strncpy(dns_ip, conn->ifaceInfo[iface].dns_2, strlen(conn->ifaceInfo[iface].dns_2));
		}

		server_ip = SBData->conn.ifaceInfo[iface].server_ip;

		SECURE_DB_INFO("Server IP [%s] Interface IP [%s] DNS Server [%s]",
			server_ip, interface_ip, dns_ip);
		a4.s_addr = inet_addr(interface_ip);

		status = ares_library_init(ARES_LIB_INIT_ALL);
		if (status != ARES_SUCCESS)
		{
			TIZEN_LOGD("ares_library_init: [%s]", ares_strerror(status));
			continue;
		}

		options.sock_state_cb = state_cb;
		optmask |= ARES_OPT_SOCK_STATE_CB;

		options.timeout = 100000000;
		optmask |= ARES_OPT_TIMEOUTMS;

		status = ares_init_options(&channel, &options, optmask);
		if(status != ARES_SUCCESS)
		{
			TIZEN_LOGD("ares_init_options: [%s]", ares_strerror(status));
			continue;
		}
		TIZEN_D_LOGD("Ares Init Success");

		ares_set_servers_csv(channel, dns_ip);

		TIZEN_D_LOGD("DNS Server Set PASS");

		ares_set_local_ip4(channel, ntohl(a4.s_addr));

		TIZEN_D_LOGD("Set Local IP Address PASS");

		SBData->dns = 0;
		SBData->dns_iface = iface;
		ares_gethostbyname(channel, host, AF_INET, callback, SBData);
		TIZEN_D_LOGD("After Get host by name");

		wait_ares(channel,SBData);
		ares_destroy(channel);
		ares_library_cleanup();

		if(SBData->dns == 1)
		{
			retval = 1;
			SECURE_DB_INFO("SBData[%p] New IP Address [%s]",SBData, conn->ifaceInfo[iface].server_ip);
			return retval;
		}
		else
		{	
			TIZEN_LOGD("SBData[%p] Resolution Failure", SBData);
		}
	}
	return retval;
}/* End of getDNSInfo */

int handleRedirection(char *location,  uint32 iface, char **reqHeaders, uint32 *headerLen, SmartBondingData *SBData)
{
	int retval = HTTP_RSP_DECODING_ERROR;
	char *tempLoc = location;
	char *host = NULL;
	char *url = NULL;
	char *newReq = NULL;

	/* Decode the location */
	decodeLocation(tempLoc,&host,&url);
	newReq = getNewRedirectReq(host,url,*reqHeaders);
	if((NULL != newReq) && (getDNSInfo(host,iface,SBData)))
	{
		free(*reqHeaders);
		*reqHeaders = NULL;
		*reqHeaders =  newReq;
		*headerLen = strlen(newReq);
		SECURE_DB_INFO("New Requset after Redirect [%s]", newReq);
		retval =  HTTP_RSP_DECODING_SUCCESS;
	}/* End of if */
	else if (NULL != newReq)
	{
		free(newReq);
		newReq = NULL;
	}
	if(NULL != host)
	{
		free(host);
	}/* End of if */

	if(NULL != url)
	{
		free(url);
	}/* End of if */

	host = NULL;
	url = NULL;
	return retval;
}/* End of handleRedirection() */

/*
* FUNCTION     : decodeLocation
* PARAMETERS   : *loc = location to be decoded
*                **host = host from loction
*                **url = url from loction
* DESCRIPTION  : This function will decode the location headers from 3XX response
				 and extract the host and url
* RETURN VALUE : void
*/
void decodeLocation(char *loc,char **host,char **url)
{
	int ret = 0;
	int offset = 0;
	int len = strlen(loc);

	if(0 == strncmp(loc,"http://",7))
	{
		offset = offset + 7;
	}/* End of if */
	ret = decode_http_find_str(loc+offset,"/");
	if(ret != -1)
	{
		*host = (char*)malloc(ret+1);
		memset(*host,0,ret+1);
		memcpy(*host,loc+offset,ret);
		*url = (char*)malloc(len-(offset+ret)+1);
		memset(*url,0,(len-(offset+ret)+1));
		memcpy(*url,loc+offset+ret,len-(offset+ret));
	}/* End of if */
	else
	{
		/* host and url are same */
		int tempLen = len-offset;
		*host = (char*)malloc(tempLen+1);
		memset(*host,0,tempLen+1);
		memcpy(*host,loc+offset,tempLen);
		*url = (char*)malloc(tempLen+1);
		memset(*url,0,tempLen+1);
		memcpy(*url,loc+offset+ret,tempLen);
	}/* End of else */
	SECURE_DB_INFO("Decode Loaction URL [%s] Host [%s]", *url , *host);
}/* End of decodeLocation() */

/*
* FUNCTION     : getNewRedirectReq
* PARAMETERS   : *host = host from loction header
*                *url = url from loction header
* DESCRIPTION  : This function will build the new HTTP
*                request after redirection response is received
* RETURN VALUE : void
*/
char *getNewRedirectReq(char *host,char *url, char *reqHeaders)
{
	int len = 0;
	int index = 0;
	int offset = 0;
	int totalLen = 0;
	int headerLen = 0;
	int numOfhead = 0;
	int reqLineLen = 0;
	char *headers[20] = {0};
	char *newReq = NULL;
	char *tempBuff = reqHeaders;

	len = decode_http_find_str(tempBuff,"\r\n");
	if(len == -1)
	{
		return NULL;
	}/*	 End of if */

	tempBuff = tempBuff+len+2;
	while((strlen(tempBuff) > 0) && (numOfhead < 20))
	{
		len = decode_http_find_str(tempBuff,"\r\n");
		if(len != 1)
		{
			if(0 != strncasecmp(tempBuff,"Host:",5))
			{
				headers[numOfhead] = (char*)malloc(len + 3);
				memset(headers[numOfhead],0,len + 3);
				memcpy(headers[numOfhead],tempBuff,len+2);
				headerLen = headerLen + len + 2;
				numOfhead++;
			}/* End of if */
			tempBuff = tempBuff + len + 2;
		}/* End of if */
		else
		{
			break;
		}/* End of else */
	}/* End of if */
	totalLen = strlen(host)+strlen(url)+headerLen+(2 * MAX_RANGE_FIELD_LEN);
	newReq = (char*)malloc(totalLen);
	if(NULL == newReq)
	{
		return NULL;
	}/* End of if */

	memset(newReq,0,totalLen);
	reqLineLen = sprintf(newReq,"%s%s%s%s","GET ",url," HTTP/1.1",END_OF_LINE);
	offset = reqLineLen + sprintf(newReq+reqLineLen,"%s%s%s","Host: ",host,END_OF_LINE);
	for(index = 0; index < numOfhead; index++)
	{
		headerLen = strlen(headers[index]);
		memcpy(newReq+offset,headers[index],headerLen);
		offset = offset+headerLen;
		free(headers[index]);
		headers[index] = NULL;
	}/* End of if */
	return newReq;
}/* End of getNewRedirectReq() */

uint32 store_interface_ip_request(char *newReq, SmartBondingData *SBData, uint32 interface_index)
{
	char *temp_req1 = NULL;
	char *temp_req2 = NULL;
	char *temp;
	int retval = -1;
	int len = -1;
	int len1 = 0;
	httpReq *req = &(SBData->req);
	len = decode_http_find_str(newReq, RANGELEN_REQ_HEADER);
	if(len != -1)
	{
		temp_req1 = malloc(strlen(newReq)+ 1);
		memset(temp_req1, 0, strlen(newReq)+ 1);
		memcpy(temp_req1,newReq,len);
		len1 = len ;
		temp = newReq + len;
		len = decode_http_find_str(temp,END_OF_LINE);
		temp = temp + len;
		memcpy(temp_req1+len1,"\r\n",2);
		req->request[interface_index] = temp_req1;
	}
	else
	{
		return retval;
	}

	if(SBData->req.Rangeheader == NULL)
	{
		len  = strlen(req->req_buff);
		temp_req2 = malloc(len + 1);
		memset(temp_req2, 0, len + 1);
		memcpy(temp_req2, req->req_buff, len);
	}
	else
	{
		len  = strlen(req->req_buff_wo_range);
		temp_req2 = malloc(len + 1);
		memset(temp_req2, 0, len + 1);
		memcpy(temp_req2, req->req_buff_wo_range, len);
	}

	req->request[(interface_index+1) % 2] = temp_req2;
	retval = 0;
	return retval;
}
