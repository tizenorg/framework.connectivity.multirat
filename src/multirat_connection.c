#include "multirat_conf.h"
#include "multirat_process.h"
#include "multirat_connection.h"
#include "multirat_libapi.h"
#include <vconf.h>
#include <vconf-keys.h>

int32 connection_interface_status(struct ifreq *ifr, char *name)
{
	int32 sock = -1;
	uint32 i = 0;
	uint32 interfaces = 0;
	struct ifconf ifconf;
	struct ifreq ifreq[10];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		TIZEN_LOGD("Error !!! while creating socket [%d] [%s]", errno, strerror(errno));
		return -1;
	}

	ifconf.ifc_buf = (char *) ifreq;
	ifconf.ifc_len = sizeof ifreq;

	if (ioctl(sock, SIOCGIFCONF, &ifconf) == -1)
	{
		TIZEN_LOGD("Error !!! while executing ioctl [%d] [%s]", errno, strerror(errno));
		CLOSE_SOCKET(sock);
		return -1;
	}

	interfaces = ifconf.ifc_len / sizeof(ifreq[0]);
	TIZEN_LOGD("Number of interfaces [%d]",interfaces);

	for (i = 0; i < interfaces; i++)
	{
		TIZEN_D_LOGD("Name of Interface [%s]", ifreq[i].ifr_name);
		if(!strncmp(ifreq[i].ifr_name, name, strlen(name)))
		{
			ioctl(sock,  SIOCGIFFLAGS, &ifreq[i]);
			if((ifreq[i].ifr_flags & IFF_UP)  && (ifreq[i].ifr_flags & IFF_RUNNING))
			{
				memcpy(ifr,&(ifreq[i]),sizeof(struct ifreq));
				CLOSE_SOCKET(sock);
				return B_TRUE;
			}
		}
	}
	CLOSE_SOCKET(sock);
	return -1;
}

int32 connection_is_ifaceup(uint32 ifaceidx, interfaceInfo *ifaceInfo,int iptype)
{
	int32 status = 0 ;
	int8 *default_iname = DEFAULT_INTERFACE;
	int8 *ifacename = NULL;
	int8 ip[INET_ADDRSTRLEN] = {0};
	struct sockaddr_in *address = NULL;
	struct sockaddr_in6 *address_ip6 = NULL;
	struct ifreq ifreq;

	if (0 == strncasecmp(default_iname, LTE, strlen(LTE)))
	{
		/*
		 * thread  0 should get interface LTE (1)
		 * and thread 1 should get interface WIFI(0)
		 */
		ifaceidx = (ifaceidx + 1) % 2;
	}

	if(ifaceidx)
	{
		ifacename = LTE_IFACE_NAME;
	}
	else
	{
		ifacename = WIFI_IFACE_NAME;
	}

	memset(&ifreq,0,sizeof(struct ifreq));
	status = connection_interface_status(&ifreq,ifacename);

	if(status == -1)
	{
		return B_FALSE ;
	}

	if(iptype)
	{
		address_ip6= (struct sockaddr_in6 *) &ifreq.ifr_addr;
		if (!inet_ntop(AF_INET6, &address_ip6->sin6_addr, ip, sizeof(ip)))
		{
			TIZEN_LOGD("Error !!! while executing inet_ntop [%d] [%s]", errno, strerror(errno));
			return B_FALSE;
		}
	}
	else
	{
		address = (struct sockaddr_in *) &ifreq.ifr_addr;
		if (!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip)))
		{
			TIZEN_LOGD("Error !!! while executing inet_ntop [%d] [%s]", errno, strerror(errno));
			return B_FALSE;
		}
	}

	memset(ifaceInfo[ifaceidx].ip, 0, INET_ADDRSTRLEN);
	strcpy(ifaceInfo[ifaceidx].ip,ip);

	return B_TRUE;
}

int32 file_thread_connServer (int32 sockFd, struct sockaddr_in *remote_addr,struct sockaddr_in6 *remote_addr_ip6, uint32 timeout,
  SmartBondingData *SBData)
{
	//int32 flags = 0;
	int32 retval = 0;
	int32 select_ret = 0;
	uint32 connTimeOut = 0;
	uint64 connect_start = 0;
	int8 tmp_ip_addr[INET6_ADDRSTRLEN];
	int32 connect_status = -1;

	if((0 != timeout))
	{
		connTimeOut = MIN(timeout, 60);
	}
	else
	{
		connTimeOut = 60;
	}

	//flags = fcntl(sockFd, F_GETFL, 0);

	if(SBData->conn.ip_family)
	{
		SECURE_DB_INFO("destIPv6 address [%s]", inet_ntop(AF_INET6,&(remote_addr_ip6->sin6_addr),tmp_ip_addr,INET6_ADDRSTRLEN));
	}
	else
	{
		SECURE_DB_INFO("destIPv4 address [%s]", inet_ntoa(remote_addr->sin_addr));
	}

	if(-1 == fcntl(sockFd, F_SETFL, O_NONBLOCK))
	{
		TIZEN_LOGD("Error !!! connection FCNTL failed [%d] [%s]", errno, strerror(errno));
		return -1;
	}

	if(SBData->conn.ip_family)
	{
		connect_status = connect(sockFd, (struct sockaddr *)remote_addr_ip6, sizeof(struct sockaddr_in6));
	}
	else
	{
		connect_status = connect(sockFd, (struct sockaddr *)remote_addr, sizeof(struct sockaddr_in6));
	}
	if(connect_status == -1)
	{
		if(errno != EINPROGRESS)
		{
			TIZEN_LOGD("Error !!! connection failure [%d] [%d] [%s]", sockFd, errno, strerror(errno));
			return -1;
		}
		retval = -1;

		struct timeval tv;
		fd_set write_fds;

		connect_start = get_time_in_sec();
		while(((get_time_in_sec() - connect_start) < connTimeOut) && ((SBData->fStream->compRspRcvdFlag)) && ((SBData->status == MAIN_START) || (SBData->file_status == NO_REDIVISION)))
		{
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			FD_ZERO(&write_fds);
			FD_SET(sockFd, &write_fds);
			select_ret = select(sockFd + 1, NULL, &write_fds, NULL, &tv);
			if(select_ret == 0)
			{
				TIZEN_LOGD("Time out on select with socket [%d]",sockFd);
				continue;
			}
			else if(select_ret == -1)
			{
				TIZEN_LOGD("Error !!! select failed [%d] [%s]", errno, strerror(errno));
				retval = -1;
			}
			else if(select_ret == 1)
			{
				int so_error;
				socklen_t slen = sizeof (so_error);
				if(getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &so_error, &slen) == 0)
				{
					if(so_error)
					{
						TIZEN_LOGD("Error !!! getsockopt failed, so_error is true [%d] [%s]", errno, strerror(errno));
					}
					else
					{
						retval = 0;
					}
				}
				else
				{
					TIZEN_LOGD("Error !!! getsockopt failed [%d] [%s]", errno, strerror(errno));
				}
			}
			break;
		}
	}
	return retval;
}

int32 get_connection_status(SmartBondingData *SBData)
{
	struct timeval tv;
	fd_set write_fds;

	int32 sockFd = SBData->socket_fd;

	int32 retval = -1;
	int32 select_ret = 0;

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	FD_ZERO(&write_fds);
	FD_SET(sockFd, &write_fds);

	TIZEN_LOGD("SBData[%p] Check Connection Status ", SBData);

	select_ret = select(sockFd + 1, NULL, &write_fds, NULL, &tv);
	if(select_ret == 0)
	{
		SBData->con_status = CONNECTION_WAIT;
		TIZEN_LOGD("Time out on select with socket [%d] SBData[%p]",sockFd, SBData);
	}
	else if(select_ret == -1)
	{
		SBData->con_status = CONNECTION_FAIL;
		TIZEN_LOGD("Error !!! select failed [%d] [%s] SBData[%p]", errno, strerror(errno), SBData);
	}
	else if(select_ret == 1)
	{
		int so_error;
		socklen_t slen = sizeof (so_error);
		if(getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &so_error, &slen) == 0)
		{
			if(so_error)
			{
				SBData->con_status = CONNECTION_FAIL;
				TIZEN_LOGD("Error !!! getsockopt failed, so_error is true [%d] [%s] SBData[%p]", errno, strerror(errno), SBData);
			}
			else
			{
				SBData->con_status = CONNECTION_SUCCESS;
				TIZEN_LOGD("Connection Success");
				retval = 0;
			}
		}
		else
		{
			SBData->con_status = CONNECTION_FAIL;
			TIZEN_LOGD("Error !!! getsockopt failed [%d] [%s] SBData[%p]", errno, strerror(errno), SBData);
		}
	}
	return retval;
}

int32 connServer (int32 sockFd, struct sockaddr_in *remote_addr,struct sockaddr_in6 *remote_addr_ip6, uint32 timeout,
  SmartBondingData *SBData)
{
	int32 retval = 0;
	int32 select_ret = 0;
	uint32 connTimeOut = 0;
	uint64 connect_start = 0;
	int8 tmp_ip_addr[INET_ADDRSTRLENG];
	int32 connect_status = -1;

	if((0 != timeout))
	{
		connTimeOut = MIN(timeout, 60);
	}
	else
	{
		connTimeOut = 60;
	}

	if(SBData->conn.ip_family)
	{
		SECURE_DB_INFO("SBData[%p] destIPv6 address [%s] timeout [%d]", SBData, inet_ntop(AF_INET6,&(remote_addr_ip6->sin6_addr),tmp_ip_addr,INET6_ADDRSTRLEN), connTimeOut);
	}
	else
	{
		SECURE_DB_INFO("SBData[%p] destIPv4 address [%s] timeout [%d]", SBData, inet_ntoa(remote_addr->sin_addr), connTimeOut);
	}

	if(-1 == fcntl(sockFd, F_SETFL, O_NONBLOCK))
	{
		TIZEN_LOGD("SBData[%p] Error !!! connection FCNTL failed [%d] [%s]", SBData, errno, strerror(errno));
		return -1;
	}
	if(SBData->conn.ip_family)
	{
		connect_status = connect(sockFd, (struct sockaddr *)remote_addr_ip6, sizeof(struct sockaddr_in6));
	}
	else
	{
		connect_status = connect(sockFd, (struct sockaddr *)remote_addr, sizeof(struct sockaddr_in6));
	}
	if(connect_status == -1)
	{
		if(errno != EINPROGRESS)
		{
			SBData->con_status = CONNECTION_FAIL;
			TIZEN_LOGD("SBData[%p] Error !!! connection failure [%d] [%d] [%s]", SBData, sockFd, errno, strerror(errno));
			return -1;
		}
		retval = -1;
		SBData->con_status = CONNECTION_FAIL;
		struct timeval tv;
		fd_set write_fds;

		connect_start = get_time_in_sec();
		while(((get_time_in_sec() - connect_start) < connTimeOut) && (SBData->cancel != 1))
		{
			tv.tv_sec = 0;
			tv.tv_usec = 500000; /* half sec */
			FD_ZERO(&write_fds);
			FD_SET(sockFd, &write_fds);
			select_ret = select(sockFd + 1, NULL, &write_fds, NULL, &tv);
			if(select_ret == 0)
			{
				SBData->con_status = CONNECTION_WAIT;
				TIZEN_LOGD("SBData[%p] Time out on select with socket [%d]",SBData, sockFd);
				continue;
			}
			else if(select_ret == -1)
			{
				SBData->con_status = CONNECTION_FAIL;
				TIZEN_LOGD("SBData[%p] Error !!! select failed [%d] [%s]", SBData, errno, strerror(errno));
				retval = -1;
			}
			else if(select_ret == 1)
			{
				int so_error;
				socklen_t slen = sizeof (so_error);
				if(getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &so_error, &slen) == 0)
				{
					if(so_error)
					{
						SBData->con_status = CONNECTION_FAIL;
						TIZEN_LOGD("SBData[%p] Error !!! getsockopt failed, so_error is true [%d] [%s]",SBData, errno, strerror(errno));
					}
					else
					{
						struct sockaddr sockname;
						unsigned int len = sizeof(sockname);
						unsigned short port = 0;
						memset(&sockname, 0, len);
						if(getsockname(sockFd, &sockname, &len) != -1)
						{
							port = ntohs(((struct sockaddr_in*)(&sockname))->sin_port);
						}
						else
						{
							TIZEN_LOGD("SBData[%p] Error !!! getsockname failed [%d] [%s]",SBData, errno, strerror(errno));
						}
						SBData->con_status = CONNECTION_SUCCESS;
						
						SECURE_DB_INFO("SBData[%p] Conection Success source_port=%hu",SBData, port);
						retval = 0;
					}
				}
				else
				{
					SBData->con_status = CONNECTION_FAIL;
					TIZEN_LOGD("SBData[%p] Error !!! getsockopt failed [%d] [%s]",SBData, errno, strerror(errno));
				}
			}
			break;
		}
	}
	else
		SBData->con_status = CONNECTION_SUCCESS;
	return retval;
}

void file_thread_connect_server(fileThread *fThread)
{
	int32 socketId = -1;
	uint32 index = 0;
	uint32 bindCount = 0;
	struct hostent *h;
	struct sockaddr_in remote_addr;
	struct sockaddr_in6 remote_addr_ip6;

	connection *conn = fThread->conn ;

	index = fThread->interface_index;

	TIZEN_LOGD("Connect Server");

	h = gethostbyname(conn->ifaceInfo[index].server_ip);

	SECURE_DB_INFO("Server IP %s For %d interface", conn->ifaceInfo[index].server_ip, index);

	//	memset(&remote_addr, 0, sizeof(struct sockaddr_in));

	if(conn->ip_family)
	{
		memset(&remote_addr_ip6, 0, sizeof(struct sockaddr_in6));
		remote_addr_ip6.sin6_family = h->h_addrtype;
		memcpy((char *) &remote_addr_ip6.sin6_addr.s6_addr, h->h_addr_list[0], h->h_length);
		remote_addr_ip6.sin6_port = htons(conn->ifaceInfo[index].server_port);
	}
	else
	{
		memset(&remote_addr, 0, sizeof(struct sockaddr_in));
		remote_addr.sin_family = h->h_addrtype;
		memcpy((char *) &remote_addr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
		remote_addr.sin_port = htons(conn->ifaceInfo[index].server_port);
	}

	while (*fThread->compRspRcvdFlag)
	{
		if(bindCount> 3)
		{
			TIZEN_LOGD("thread ID Tried Connect More Times File Thread");
			socketId = -1;
			break;
		}

		socketId = conn_get_socket_bind(conn->ifaceInfo[index].ip,index,conn->ip_family);
		if(socketId < 0)
		{
			socketId = -1;
			usleep(100000);
			bindCount++;
			continue;
		}

		TIZEN_LOGD("Socket ID [%d]",socketId);

		if(-1 == file_thread_connServer(socketId, &remote_addr,&remote_addr_ip6, fThread->SBData->timeout, fThread->SBData))
		{
			CLOSE_SOCKET(socketId);
			socketId = -1;
		}
		break;
	}
	if (((*fThread->compRspRcvdFlag)== 0) && (socketId >= 0))
	{
		TIZEN_LOGD("socket compRspRcvdFlag 0 and socket thread id [%d]", socketId);
		CLOSE_SOCKET(socketId);
		socketId = -1;
	}
	fThread->socketId = socketId;
	return;
}

void connect_server(RangeRequestThread *rrthread)
{
	int32 socketId = -1;
	uint32 index = 0;
	uint32 bindCount = 0;
	int8 *default_iname = DEFAULT_INTERFACE;
	struct hostent *h;
	struct sockaddr_in remote_addr;
	struct sockaddr_in6 remote_addr_ip6;
	connection *conn = rrthread->conn ;

	index = rrthread->threadId;

	if (0 == strncasecmp(default_iname, LTE, strlen(LTE)))
	{
		index = (index +1) % 2;
	}/* End of if */

	h = gethostbyname(conn->ifaceInfo[index].server_ip);

	SECURE_DB_INFO("Server IP [%s] For [%d] interface", conn->ifaceInfo[index].server_ip, index);

	//	memset(&remote_addr, 0, sizeof(struct sockaddr_in));

	if(conn->ip_family)
	{
		memset(&remote_addr_ip6, 0, sizeof(struct sockaddr_in6));
		remote_addr_ip6.sin6_family = h->h_addrtype;
		memcpy((char *) &remote_addr_ip6.sin6_addr.s6_addr, h->h_addr_list[0], h->h_length);
		remote_addr_ip6.sin6_port = htons(conn->ifaceInfo[index].server_port);
	}
	else
	{
		memset(&remote_addr, 0, sizeof(struct sockaddr_in));
		remote_addr.sin_family = h->h_addrtype;
		memcpy((char *) &remote_addr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
		remote_addr.sin_port = htons(conn->ifaceInfo[index].server_port);
	}

	while (*rrthread->compRspRcvdFlag)
	{
		if(bindCount> 3)
		{
			TIZEN_LOGD("thread ID [%d] Tried Connect More Times",rrthread->threadId);
			socketId = -1;
			break;
		}

		socketId = conn_get_socket_bind(conn->ifaceInfo[index].ip,index,conn->ip_family);
		if(socketId < 0)
		{
			socketId = -1;
			usleep(100000);
			bindCount++;
			continue;
		}

		TIZEN_LOGD("Socket ID [%d]",socketId);

		if(-1 == connServer(socketId, &remote_addr,&remote_addr_ip6,rrthread->SBData->timeout, rrthread->SBData))
		{
			CLOSE_SOCKET(socketId);
			socketId = -1;
		}
		break;
	}
	if (((*rrthread->compRspRcvdFlag)== 0) && (socketId >= 0))
	{
		TIZEN_LOGD("socket compRspRcvdFlag 0 and socket thread id [%d]", socketId);
		CLOSE_SOCKET(socketId);
		socketId = -1;
	}
	conn->sockId[rrthread->threadId] = socketId;
	rrthread->socketId = socketId;
	return;
}

uint32 is_interface_up(int8* ifacename, interfaceInfo *ifaceinfo,int iptype)
{
	int32 status = 0 ;
	int8 ip[INET_ADDRSTRLEN] = {0};
	struct ifreq ifreq;

	memset(&ifreq,0,sizeof(struct ifreq));
	status = connection_interface_status(&ifreq, ifacename);
	if (status!= -1)
	{
		if(iptype)
		{
			struct sockaddr_in6 *address_ip6 = (struct sockaddr_in6 *) &ifreq.ifr_addr;
			if (!inet_ntop(AF_INET6, &address_ip6->sin6_addr, ip, sizeof(ip)))
			{
				TIZEN_LOGD("socket error");
				return B_FALSE;
			}
		}
		else
		{
			struct sockaddr_in *address = (struct sockaddr_in *) &ifreq.ifr_addr;
			if (!inet_ntop(AF_INET, &address->sin_addr, ip, sizeof(ip)))
			{
				TIZEN_LOGD("socket error");
				return B_FALSE;
			}
		}


		if (!strncmp(ifacename, LTE_IFACE_NAME ,  strlen(ifacename)))
		{
			memset(ifaceinfo[LTE_INTERFACE].ip , 0 , INET_ADDRSTRLENG);
			strcpy(ifaceinfo[LTE_INTERFACE].interface_name, ifreq.ifr_name);
			strcpy(ifaceinfo[LTE_INTERFACE].ip,ip);
			SECURE_DB_INFO("IP address of LTE [%s]",ip);
			return B_TRUE;
		}
		else if (!strncmp(ifacename, WIFI_IFACE_NAME , strlen(ifacename)))
		{
			int32 is_on = VCONFKEY_MOBILE_HOTSPOT_MODE_NONE;
			memset(ifaceinfo[WIFI_INTERFACE].ip , 0 , INET_ADDRSTRLENG);
			strcpy(ifaceinfo[WIFI_INTERFACE].interface_name, ifreq.ifr_name);
			strcpy(ifaceinfo[WIFI_INTERFACE].ip,ip);
			SECURE_DB_INFO("IP address of WiFi [%s]", ip);

			vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &is_on);
			if(is_on != VCONFKEY_MOBILE_HOTSPOT_MODE_NONE)
			{
				TIZEN_LOGD("Wi-Fi is Not in Normal Wi-Fi Mode");
				return B_FALSE;
			}
			return B_TRUE;
		}
	}
	TIZEN_LOGD ("Interface name [%s] is not found", ifacename);
	return B_FALSE;
}

uint32 is_both_interface_avail(interfaceInfo *ifaceInfo,int iptype)
{
	uint32 lteFlag = 0;
	uint32 wifiFlag = 0;

	lteFlag = is_interface_up(LTE_IFACE_NAME, ifaceInfo,iptype);
	TIZEN_LOGD ("MultiRat Main Thread lte [%u]", lteFlag);

	wifiFlag = is_interface_up(WIFI_IFACE_NAME, ifaceInfo,iptype);
	TIZEN_LOGD ("MultiRat Main Thread wifi [%u]", wifiFlag);

	return (lteFlag && wifiFlag);
}

int32 conn_get_socket_bind(int8 *ip, int ifaceidx, int iptype)
{
	int32 socket_fd = -1;
	int32 bind_ret = -1;
	struct sockaddr_in sa_loc;
	struct sockaddr_in6 sa_loc6;

	memset(&sa_loc6, 0, sizeof(struct sockaddr_in6));
	memset(&sa_loc, 0, sizeof(struct sockaddr_in));

	if(iptype)
	{
		socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
		if (socket_fd < 0)
		{
			TIZEN_LOGD("Error !!! socket creation failed [%d] [%s]", errno, strerror(errno));
			return -1;
		}
		sa_loc6.sin6_family = AF_INET6;
		sa_loc6.sin6_port = htons(0);
		inet_pton(AF_INET6,ip,&(sa_loc6.sin6_addr));
	}
	else
	{
		socket_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (socket_fd < 0)
		{
			TIZEN_LOGD("Error !!! socket creation failed [%d] [%s]", errno, strerror(errno));
			return -1;
		}
		sa_loc.sin_family = AF_INET;
		sa_loc.sin_port = htons(0);
		sa_loc.sin_addr.s_addr = inet_addr(ip);
	}

	if(iptype == 0)
	{
		bind_ret = bind(socket_fd,(struct sockaddr *)&sa_loc, sizeof(struct sockaddr));
	}
	else
	{
		bind_ret = bind(socket_fd,(struct sockaddr *)&sa_loc6, sizeof(struct sockaddr_in6));
	}

	SECURE_DB_INFO("Binding [%d] on IP Address [%s]",socket_fd,ip);
	if(bind_ret == -1)
	{
		TIZEN_LOGD("Error !!! bind failed [%d] [%s]", errno, strerror(errno));
		CLOSE_SOCKET(socket_fd);
		return -1;
	}
	SECURE_DB_INFO("Binding to the IP address[%s] Successful",ip);
	return socket_fd;
}

int32 conn_poll(int32 socketId, uint32 timeout)
{
	struct pollfd rcvfd;
	memset(&rcvfd, 0, sizeof(struct pollfd));
	rcvfd.fd = socketId;
	rcvfd.events = POLLIN;

	return poll(&rcvfd, 1, timeout);
}

int32 file_thread_conn_poll(int32 socket, SmartBondingData *SBData)
{
	int32 pollret = 0;
	uint32 pollStartTime = get_time_in_sec();
	while((SBData->fStream->compRspRcvdFlag) && (((SBData->status == MAIN_START) || (SBData->file_status == NO_REDIVISION)) && ((get_time_in_sec() - pollStartTime) < 30)))
	{
		pollret = 0;
		pollret = conn_poll(socket, 200);
		if (pollret < 0)
		{
			TIZEN_LOGD("Error !!! watchdog thread pollfd failed");
			break;
		}
		else if(pollret == 0)
		{
			TIZEN_D_LOGD("Timeout on File Thread Poll");
			continue;
		}
		else
		{
			TIZEN_D_LOGD("File Thread Response");
			break;
		}
	}
	return pollret;
}


int32 watchdog_conn_poll(int32 socket, SmartBondingData *SBData)
{
	int32 pollret = 0;
	uint32 pollStartTime = get_time_in_sec();
	while((SBData->cthread->threadStatus != THREAD_FINISH) && ((get_time_in_sec() - pollStartTime) < 30))
	{
		pollret = 0;
		pollret = conn_poll(socket, 2000);
		if (pollret < 0)
		{
			TIZEN_LOGD("Error !!! watchdog thread pollfd failed");
			break;
		}
		else if(pollret == 0)
		{
			TIZEN_D_LOGD("Timeout on Watch Dog Poll");
			continue;
		}
		else
		{
			TIZEN_D_LOGD("WatchDog Received Response");
			break;
		}
	}
	return pollret;
}

void PollThread_poll(int32 socket, SmartBondingData *SBData, uint32 timeout_check)
{
	int32 pollret = 0;
	uint32 pollStartTime = get_time_in_sec();
    while((SBData->PollThrd->threadStatus != THREAD_FINISH) && ((get_time_in_sec() - pollStartTime) < 30))
    {
        pollret = 0;
		pollret = conn_poll(socket, timeout_check);
		if (pollret < 0)
		{
			TIZEN_LOGD("Error !!! Poll Thread pollfd failed");
			break;
		}
		else if(pollret == 0)
		{
			TIZEN_D_LOGD("Timeout on Pollthread Poll");
			continue;
		}
		else
		{
			TIZEN_D_LOGD("Poll Thread Received Data");
			break;
		}
	}
	return ;
}

void lib_conn_poll(int32 socket, SmartBondingData *SBData)
{
	int32 pollret = 0;
	while((SBData->cancel != 1))
	{
		pollret = 0;
		pollret = conn_poll(socket, 1000);
		if (pollret < 0)
		{
			TIZEN_LOGD("Error !!! Libapi pollfd failed");
			break;
		}
		else if(pollret == 0)
		{
			TIZEN_D_LOGD("Timeout on Libapi Poll");
			continue;
		}
		else
		{
			TIZEN_D_LOGD("App Read Received Data to Read");
			break;
		}
	}
	return;
}

int32 read_conn_poll(int32 socket, SmartBondingData *SBData)
{
	int32 pollret = 0;
	uint32 pollStartTime = get_time_in_sec();
	while((SBData->cancel != 1) && ((get_time_in_sec() - pollStartTime) < SBData->timeout))
	{
		pollret = 0;
		pollret = conn_poll(socket, 200);
		if (pollret < 0)
		{
			TIZEN_LOGD("Error !!! Read pollfd failed");
			break;
		}
		else if(pollret == 0)
		{
			TIZEN_D_LOGD("Timeout on Read Poll");
			continue;
		}
		else
		{
			TIZEN_D_LOGD("Received Data to Read");
			break;
		}
	}
	return pollret;
}

