#ifndef MULTIPROCESS_H_
#define MULTIPROCESS_H_

#include "multirat_SB_http.h"
#include "multirat_decode_http.h"
#include "multirat_range_request_thread.h"
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/**
 * @brief                           validate and store http response
 * @param[in]         rsp           response buffer
 * @param[in]         headers_len   header length
 * @param[in]         SBData        smartbonding Data
 * @return                          void
 */
void store_check_http_response(SmartBondingData *SBData);

/**
 * @brief                           store and process http request
 * @param[in]           req         request buffer
 * @param[in]           SBData      smart bonding data object
 * @return                          void
 */
void store_http_request(int8*req, SmartBondingData *SBData);

/**
 * @brief                           multirat enbaling function
 * @param[in]         SBData        smart bonding object
 * @return                          status indicating if multirat is enabled
 * @retval            1             multirat enabled
 * @retval            0             multirat not enabled
 */
uint32 should_enable_multirat(SmartBondingData *SBData);

/**
 * @brief                           deallocating memory while exiting from SB
 * @param[in]         SBData        SmartBondingData
 * @return                          void
 */
void smart_bonding_exit(SmartBondingData *SBData);

/**
 * @brief                           gives smartbonding object size
 * @param[in]           SBData      smartbondoing object size
 * @return                          void
 */
void get_object_size(httpResp *resp);

/**
 * @brief                           gives time in micro seconds
 * @param[in]                       void
 * @return                          time in microsec
 */
uint64 get_time_in_microsec();

/**
 * @brief                           get time in seconds
 * @param[in]         SBData        smart bonding data
 * @return                          time in seconds
 */
uint64 get_time_in_sec();

/**
 * @brief                           get the temperature level
 * @param[in]                       void
 * @return                          temeparure
 * @retval              0           temparature below threshold
 * @retval              1           temperature level above threshold
 */
int getTempLevel(SmartBondingData *SBData);

/**
 * @brief                           get serial input output level from dbus
 * @param[in]                       void
 * @return                          serial input output level
 * @retval              -1          error
 */
int get_siop_level(void);

/**
 * @brief                                     Checks whether multirat can be enabled and start watch dog thread
 * @param[in]           SBSessionIdentifier   session identifier
 * @param[in]           buffer                received response from server
 * @param[in]           my_nread              length of response received from server
 */
void start_watchdog(SmartBondingData *SBData, int8 *buffer, int32 my_nread);

/**
 * @brief                                     Adds range header to request recieved from client,
 and sets length for new req
 * @param[in]           req                   request received from client
 * @param[in]           rangeStart            range start
 * @param[in]           bytesRead             offset
 * @param[in]           rangeEnd              range end
 * @param[in]           length                length of new request
 * @return              newRequest            newRequest with Range Header
 */

int8 *get_new_req(int8 *req, uint64 rangeStart, uint64 bytesRead, uint64 rangeEnd, uint32 *length, uint32 len, int32 proxy);


/**
 * @brief                                     Handles connection with server,
 and sends request to server
 * @param[in]           req                   HTTP req to be sent to server
 * @param[in]           reqLen                length of req to be sent
 * @param[in]           socket                socket fd
 * @param[in]           SBData                to access ip, port and timeout
 * @retval              -1                    on connect error
 * @retval               0                    on success
 */
int32 send_req(int8 *req, uint32 reqLen,int32 socket, uint32 index, SmartBondingData *SBData);

void reset_stats(StatDetails *stat);
void getHost(char **host, char *reqHeaders);
int getDNSInfo(char *host, int iface, SmartBondingData *SBData);
int handleRedirection(char *location,  uint32 iface, char **reqHeaders, uint32 *headerLen, SmartBondingData *SBData);
char *getNewRedirectReq(char *host,char *url, char *reqHeaders);
void decodeLocation(char *loc,char **host,char **url);
uint32 store_interface_ip_request(char *newReq, SmartBondingData *SBData, uint32 interface_index);
#endif
