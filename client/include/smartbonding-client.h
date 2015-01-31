/*
 * Smart bonding service client
 *
 * Copyright (c) 2013 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __SMARTBONDING_CLIENT_H__
#define __SMARTBONDING_CLIENT_H__

#ifdef __cplusplus
extern "C" {
#endif
#define INET_ADDRSTRLENG 50

typedef enum {
	SMBD_ERR_NONE = 0x00,
	SMBD_ERR_UNKNOWN = -999,
	SMBD_ERR_POLICY_OFF,
	SMBD_ERR_PERMISSION_DENIED,
	SMBD_ERR_IN_PROGRESS,
	SMBD_ERR_INVALID_PARAMETER,
} smbd_err_t;

typedef enum {
	SMBD_EVENT_USER_OPTION_OK,
	SMBD_EVENT_USER_OPTION_CANCEL,
	SMBD_EVENT_CELLULAR_INFO,
	SMBD_EVENT_WIFI_INFO,
	SMBD_EVENT_SMARTBONDING_STATUS,
	SMBD_EVENT_DATA,
} smbd_event_t;

typedef struct {
	char *dev_name;
	char *ip_addr;
	char *proxy;
	int sig_strength;
	char *active;
} smbd_cellular_info_t;

typedef struct {
	char proxy[INET_ADDRSTRLENG];
	char dns_1[INET_ADDRSTRLENG];
	char dns_2[INET_ADDRSTRLENG];
} smbd_cellular_profile_info_t;

typedef struct
{
	/** Event Status */
	smbd_err_t Error;
	/** Asynchronous event */
	smbd_event_t Event;
	/* Event data */
	void *EventData;
} smbd_event_info_t;

/**
 * @brief This callback will receive different types of event data.
 * @param[out] event_info All information related to the event
 *		SMBD_EVENT_USER_OPTION_OK - For popup OK button press
 *		SMBD_EVENT_USER_OPTION_CANCEL - For popup CANCEL button press
 *			Second parameter 'user_data' will have the data sent
 *			during the smart_bonding_start() API
 *		SMBD_EVENT_CELLULAR_INFO - Cellular event with all data
 *			smbd_cellular_info_t in event's EventData
 *		SMBD_EVENT_WIFI_INFO - Wi-Fi event with its signal strength
 *			in event's EventData
 *		SMBD_EVENT_SMARTBONDING_STATUS - Smartbonding status event
 *			with its current status in event's EventData
 * @param[out] user_data The data sent by the caller during smart_bonding_start() API
 * 		in case of SMBD_EVENT_USER_OPTION_OK/SMBD_EVENT_USER_OPTION_CANCEL
 * See also smart_bonding_start()
 */
typedef void(*smartbonding_cb)(smbd_event_info_t event_info, void *user_data);

/**
 * @brief API to initialize smart bonding library.
 * This init call is mandatory before using any other smart bonding APIs.
 * @return 0 if initialization successful, otherwise negative error value.
 * @retval #SMBD_ERR_NONE  Successful
 */
int smart_bonding_init(void);

/**
 * @brief API to de-initialize smart bonding library.
 * This de-init call is mandatory after the usage of smart bonding module.
 * @return 0 if de-initialization successful, otherwise negative error value.
 * @retval #SMBD_ERR_NONE  Successful
 */
int smart_bonding_deinit(void);

/**
 * @brief API to start smart bonding.
 * @param[in] file_name The name of the file being downloaded
 * @param[in] file_size The size of the file being downloaded
 * @param[in] callback The callback which will receive user's choice of selection
 * @param[in] user_data The user data sent by the caller
 * @return 0 on success, otherwise negative error value.
 * @retval #SMBD_ERR_NONE  Successful
 */
int smart_bonding_start(char *file_name, int file_size,
		smartbonding_cb callback, void *user_data);

/**
 * @brief API to stop smart bonding.
 * @param[in] user_data The user data sent by the caller, same as the one
 * 			sent to the smart_bonding_start() API
 * @return 0 on success, otherwise negative error value.
 * @retval #SMBD_ERR_NONE  Successful
 */
int smart_bonding_stop(void *user_data);

void smart_bonding_notify_interface_usage(const char *message);

void get_proxy_ip_port(char *proxy_ip, int *proxy_port);

void get_dns_ip(char *dns_1, char *dns_2);

#ifdef __cplusplus
}
#endif

#endif /* __SMARTBONDING_CLIENT_H__ */
