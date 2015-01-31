#ifndef MULTISOCKET_H_
#define MULTISOCKET_H_

#include "multirat_SB_http.h"

/**
 * @brief                            multisocket initialization
 * @param[in]           objmsInput   multisocket object input
 * @param[in]           objConn      objectConnection
 * @param[in]           SBData       SmartBonding Data
 * @retval                           void
 */
void multisocket_init(MultiSockInput *mSockInput, SmartBondingData *SBData);

/**
 * @brief                           start multi socket thread
 * @param[in]           msocket     multisocket object
 * @return	                status if multisocket has started
 * @retval              0           multisocket has started
 * @retval              1           multisocket has not started
 */

uint32 multisocket_start(SmartBondingData *SBData);

/**
 * @brief                            read from multi_socket
 * @param[in]           appBuff      application buffer
 * @param[in]           maxAppLen    max application bufferlength
 * @param[in]           msocket      multisocket object
 * @return	                 length of response read
 */

int32 multisocket_read(int8 *appBuff,uint32 maxAppLen, SmartBondingData *SBData);

/**
 * @brief                           read from multisocket during sync operation
 * @param[in]           appBuff     application buffer
 * @param[in]           maxAppLen   max application buffer length
 * @param[in]           msocket     multisocket object
 * @return                          length of response read
 */

int32 multisocket_read_sync(int8 *appBuff, uint32 maxAppLen, SmartBondingData *SBData);

/**
 * @brief                            exitfrom multisocket
 * @param[in]           msocket      multisocket object
 * @return	                          void
 */
void multisocket_exit(MultiSocket *msocket);
/**
 * @brief                            get first range request from multisocket
 * @param[in]           msocket      multisocket object
 * @return                           first response status
 * @retval              -2           first response status pending
 * @retval              -1           first response status failed
 * @retval              0            first response status success
 */
int32 multisocket_get_firstrange_status(MultiSocket *msocket);

int32 read_from_buffer(SmartBondingData *SBData,int8 *buffer, uint32 size, int32 *my_nread);

uint32 is_multirat_read(SmartBondingData *SBData);
#endif /* MULTISOCKET_H_ */

