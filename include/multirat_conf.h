#ifndef _MULTIRAT_MAIN__
#define _MULTIRAT_MAIN__

#include "multirat_SB_http.h"

#define MAX_CONF_VAL_SIZE             (50)
#define EXPECTED_BYTE                 (524288)
#define MULTIRAT_BLOCK_DIV            (20)
#define MULTIRAT_BLOCK_DIV_CON        (10)
#define MIN_MULTIRAT_BLOCK_SIZE       (1048576)
#define MIN_MULTIRAT_BLOCK_SIZE_CON   (2*1048576)
#define MAX_MULTIRAT_BLOCK_SIZE       (5*1024*1024)
#define SLEEP_TIME                    (100000)
#define MULTIRAT_UPPER_LIMIT          (5242880)
#define MULTIRAT_LOWER_LIMIT          (10*1048576)
#define MULTIRAT_LOWER_LIMIT_TWO_CHUNK (15*1048576)
#define KEEPALIVE_SUPPORT             0
#define DEFAULT_INTERFACE             "wlan0"
#define MAIN_SOCKET_DEFAULT           0  /* Change to 1 if LTE is default */
#define SPEED_TIMEOUT                 (30)
#define BLOCK_SIZE_SPEED              (32764)
#define MIN_SIZE_TO_HANDOVER          (1048576)
#define MIN_LAST_CHUNK                (3145728)
#define MIN_DATA_FOR_SPEED            (131072)

#define MAX_JUMP                      (10)
#define MIN_BLOCK_SIZE                (32768)
#define MAX_BLOCK_SIZE                (1048576)
#define MIN_BLOCK_SIZE_SPEED          (4*32768)

#define MULTIRAT_SIZE_THRESHOLD       (30*1048576)

#define MIN_FILE_NODE_SIZE            (20*1048576)/*File thread remain active if filenode>this*/
#define FILE_THREAD_SOCK_CREATE       1
#define FILE_THREAD_SOCK_READ         2

#define MULTIRAT_TEMP_THRESHOLD       2
#define MULTIRAT_CHUNK_SIZE           (20*1048576)
#define BLOCK_TIME_OUT                (8*1000*1000)
#define TEMP_TIME_OUT                 (3*1000*1000)

#define LTE_IFACE_NAME                "rmnet0"
#define WIFI_IFACE_NAME               "wlan0"
#define LTE                           "lte"

#define WATCH_DOG_CONNECT_TIMEOUT     2

#define USER_OK 1
#define USER_CANCEL 2
#define USER_POP_UP 3

/**
 * @brief                           get intance of multirat configuration
 * @param[in]                       none
 * @return                          multirate configuration object
 */
struct multirat_configuration* multirat_configuration_get_instance();

/**
 * @brief                           read the multirate configuartion data
 * @param[in]                       None
 * @return
 * @retval            TRUE          read data Success
 * @retval            FALSE	      read data Failure
 */
int multirat_configuration_readdata();

/**
 * @brief                           get multirat configuartion
 * @param[in]         data          None
 * @return                          void
 * @retval
 */
void multirat_configuration_get_configuration(int8 *data);

/**
 * @brief                           print entry value for multirate configuartion
 * @param[in]                       void
 * @return                          void
 */
void multirat_configuration_print_entry_value();

/**
 * @brief                           set the default value for multirate configuartion
 * @param[in]                       void
 * @return                          void
 */
void multirat_configuration_set_default_value(void);

/**
 * @brief                           get threshold multirat configuration
 * @param[in]                       none
 * @return                          multirate threasold value
 */
int32 get_multirat_threshold();

/**
 * @brief                           get threshold temparature  configuartion
 * @param[in]                       none
 * @return                          default temparture
 */
int32 get_multirat_temp_threshold();

uint32 lib_init_success(void);

uint32 smartbonding_client_init(void);

#endif


