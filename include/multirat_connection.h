#ifndef MULTIRAT_CONNECTION_H_
#define MULTIRAT_CONNECTION_H_

#include "multirat_SB_http.h"
#include "multirat_watch_dog_thread.h"

enum interfaceName {
	 WIFI_INTERFACE = 0,
	 LTE_INTERFACE,
	 MAX_INTERFACE
};


/**
 * @brief                              connect to server
 * @param[in]          threadId        thread number
 * @param[in]          compRspRcvdFlag response flag
 * @param[in]          rrthread        range request thread
 * @return                             socketID
 * @retval             socketID
 */

void connect_server(RangeRequestThread *rrthread);

/**
 * @brief                            connection status of the given
 *                                   interface
 * @param[in]          ifr           structure storing interface information
 * @param[in]          name          name of the interface
 * @return                           integer indicating connection status
 * @retval             B_TRUE        if interface is up
 * @retval             -1            error
 * @retval             0             error
 */

int32 connection_interface_status(struct ifreq *ifr, int8 *name);

/**
 * @brief                            gives the connection status of the interface
 * @param[in]          ifaceidx      Interface index
 * @param[in]          name          name of the interface
  * @param[in]          iptype     ip address type  ipv4 =0 /ipv6 =1
 * @return                           interface up or not
 * @retval             B_TRUE        interface is up
 * @retval             B_FALSE       interface is down
 */

int32 connection_is_ifaceup(uint32 ifaceidx, interfaceInfo *ifaceInfo, int iptype);

/**
 * @brief                            connection to the remote address
 * @param[in]          sockFd        socket FD
 * @param[in]          remote_addr   remote address after DNS resolution
 * @param[in]          remote_addr_ip6   remote address after DNS resolution
 * @param[in]          timeout       time out for connection attempts
 * @param[in]          SBData        smart bonding handler
 * @return                           connected to server or not
 * @retval             -1            error in connection
 * @retval              0            connected successfully
 */

int32 connServer (int32 sockFd, struct sockaddr_in *remote_addr,struct sockaddr_in6 *remote_addr_ip6,
		  uint32 timeout,SmartBondingData *SBData);

/**
 * @brief                            connection to the remote address
 * @param[in]          sockFd        socket FD
 * @param[in]          remote_addr   remote address after DNS resolution
 * @param[in]          remote_addr_ip6   remote address after DNS resolution
 * @param[in]          timeout       time out for connection attempts
 * @param[in]          SBData        smart bonding handler
 * @return                           connected to server or not
 * @retval             -1            error in connection
 * @retval              0            connected successfully
 */

int32 file_thread_connServer (int32 sockFd, struct sockaddr_in *remote_addr,struct sockaddr_in6 *remote_addr_ip6,
		uint32 timeout,  SmartBondingData *SBData);



uint32 is_both_interface_avail(interfaceInfo *ifaceInfo,int iptype);

/**
 * @brief                            to check if interface is up
 * @param[in]          ifacename     interface name
 * @param[in]          ifaceinfo     interface information
 * @return                           interfae available or not
 * @retval             B_TRUE        interface available
 * @retval             B_FALSE       interface not available
 */

uint32 is_interface_up(int8* ifacename, interfaceInfo *ifaceinfo,int iptype);

/**
 * @brief                            bind to the address given as param
 * @param[in]          ip            ip address to bind
 * @return                           socket FD if successful
 * @retval             socketFD      socket fd if bind successful
 * @retval            -2             bind failed
 */

int32 conn_get_socket_bind(int8 *ip, int ifaceidx, int iptype);
/**
 * @brief                           poll in the given socket and timeout
 * @param[in]          socketId     socketID where polling should happen
 * @param[in]          timeout      polling timeout
 * @return                          return values from poll function
 * @retval             -1           socket error
 * @retval             0            socket time out
 * @retval             1            polling done successfully
 */

int32 conn_poll(int32 socketId, uint32 timeout);
int32 watchdog_conn_poll(int32 socket, SmartBondingData *SBData);
void file_thread_connect_server(fileThread *fThread);
int32 file_thread_conn_poll(int32 socket, SmartBondingData *SBData);
void PollThread_poll(int32 socket, SmartBondingData *SBData, uint32 timeout_check);
void lib_conn_poll(int32 socket, SmartBondingData *SBData);
int32 read_conn_poll(int32 socket, SmartBondingData *SBData);
int32 get_connection_status(SmartBondingData *SBData);

#endif
