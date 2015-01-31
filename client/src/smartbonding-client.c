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

#include <glib.h>
#include <errno.h>
#include <gio/gio.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "multirat_SB_http.h"
#include "smartbonding-client.h"

#define DBUS_REPLY_TIMEOUT (120 * 1000)
#define SMBD_SERVICE_DBUS		"net.smartbonding"
#define SMBD_PATH_DBUS			"/org/tizen/smartbonding"
#define SMBD_SERVICE_INTERFACE		"org.tizen.smartbonding"
#define SMBD_SIGNAL_PROPERTYCHANGED	"PropertyChanged"
#define SMBD_SIGNAL_USERRESPONSE	"UserResponse"
#define SMBD_SIGNAL_VALUE_CELLULAR	"cellular_device_info"
#define SMBD_SIGNAL_VALUE_WIFI		"wifi_device_info"
#define SMBD_SIGNAL_VALUE_SMARTBONDING	"smartbonding"
#define SMBD_SIGNAL_VALUE_DATA		"data"
#define SMBD_SIGNAL_VALUE_USERRESPONSE	"user_response"
#define VCONF_SMART_BONDING_POLICY "file/private/wifi/network_bonding"

typedef enum {
	SMART_BONDING_WIFI_ONLY = 0x00,
	SMART_BONDING_SPEED_PRIORITIZED = 0x01,
} SMART_BONDING_TYPES;

struct gdbus_connection_data {
	GDBusConnection *connection;
	int conn_ref_count;
	GCancellable *cancellable;
};

struct _smartbonding_cb_s {
	smartbonding_cb cb;
	void *action_user_data;
};

typedef struct {
	smartbonding_cb cb;
	void *user_data;
	guint32 handle;
} event_info_t;

static GSList *handle_list = NULL;
static struct _smartbonding_cb_s smartbonding_callbacks = { 0, };
static struct gdbus_connection_data gdbus_conn = { NULL, 0, NULL };
static guint gdbus_conn_sub_id_smbd_cellular = 0;
//static guint gdbus_conn_sub_id_smbd_wifi = 0;
static guint gdbus_conn_sub_id_smbd_smartbonding = 0;
static guint gdbus_conn_sub_id_smbd_user = 0;
static smbd_cellular_profile_info_t smbd_cellular_profile_info;

static GDBusConnection *_dbus_get_gdbus_conn(void)
{
	return gdbus_conn.connection;
}

void get_proxy_ip_port(char *proxy_ip, int *proxy_port)
{
	if(strcmp(smbd_cellular_profile_info.proxy,"") == 0)
		return;
	else
	{
		int len = 0;
		char *temp = NULL;
		temp = strchr(smbd_cellular_profile_info.proxy,':');
		if(temp != NULL)
		{
			len = (int)(temp - smbd_cellular_profile_info.proxy);
			memcpy(proxy_ip, smbd_cellular_profile_info.proxy, len);
			*proxy_port = atoi(smbd_cellular_profile_info.proxy + len + 1);

			SECURE_DB_INFO("Proxy IP %s", proxy_ip);
			SECURE_DB_INFO("Proxy PORT %d", *proxy_port);
		}
	}
	return;
}

void get_dns_ip(char *dns_1, char *dns_2)
{
	if((strcmp(smbd_cellular_profile_info.dns_1,"")))
	{
		memcpy(dns_1,smbd_cellular_profile_info.dns_1, strlen(smbd_cellular_profile_info.dns_1));
		SECURE_DB_INFO("DNS %s", smbd_cellular_profile_info.dns_1);
	}
	if((strcmp(smbd_cellular_profile_info.dns_2,"")))
	{
		memcpy(dns_2,smbd_cellular_profile_info.dns_2, strlen(smbd_cellular_profile_info.dns_2));
		SECURE_DB_INFO("DNS %s", smbd_cellular_profile_info.dns_2);
	}
	return;
}

static GCancellable *_dbus_get_gdbus_cancellable(void)
{
	return gdbus_conn.cancellable;
}

static guint32 _handle_remove_with_user_data(void *data)
{
	GSList *list = handle_list;
	guint32 handle_id = 0;

	while (list) {
		event_info_t *temp = (event_info_t *)list->data;
		if (temp->user_data == data) {
			TIZEN_LOGD("Removed the handle - [%d] from the list", temp->handle);

			/* Get the handle id to pass the same to daemon for cleanup */
			handle_id = temp->handle;
			handle_list = g_slist_remove(handle_list, temp);
			g_free(temp);
			break;
		}

		list = g_slist_next(list);
	}

	return handle_id;
}

static void _handle_remove_post_event_send(guint handle, gboolean user_option)
{
	GSList *list = handle_list;
	smbd_event_info_t event_info = { 0, };

	while (list) {
		event_info_t *temp = (event_info_t *)list->data;
		if (temp->handle != handle) {
			list = g_slist_next(list);
			continue;
		}

		if (temp->cb != NULL) {
			if (user_option) {
				TIZEN_LOGD("Sending SMBD_EVENT_USER_OPTION_OK");

				event_info.Event = SMBD_EVENT_USER_OPTION_OK;
				event_info.Error = SMBD_ERR_NONE;

				temp->cb(event_info, temp->user_data);
			} else {
				TIZEN_LOGD("Sending SMBD_EVENT_USER_OPTION_CANCEL");

				event_info.Event = SMBD_EVENT_USER_OPTION_CANCEL;
				event_info.Error = SMBD_ERR_NONE;

				temp->cb(event_info, temp->user_data);
			}
		}

		break;
	}
}

static int __error_string_to_enum(const char *error)
{
	TIZEN_LOGD("Passed error value [%s]\n", error);

	if (error == NULL)
		return SMBD_ERR_UNKNOWN;

	else if (NULL != strstr(error, ".PermissionDenied"))
		return SMBD_ERR_PERMISSION_DENIED;
	else if (NULL != strstr(error, ".InProgress"))
		return SMBD_ERR_IN_PROGRESS;
	return SMBD_ERR_UNKNOWN;
}

static void __dbus_reply(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	smbd_err_t Error = SMBD_ERR_NONE;
	//GVariant *dbus_result;

	TIZEN_LOGD("DBus reply callback\n");

	conn = G_DBUS_CONNECTION (source_object);
	//dbus_result = g_dbus_connection_call_finish(conn, res, &error);
	g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		TIZEN_LOGD("Smartbonding action failed. Error Msg [%s]\n", error->message);
		Error = __error_string_to_enum(error->message);
		g_error_free(error);
	}

	if (Error != SMBD_ERR_NONE) {
		TIZEN_LOGD("Smartbonding action failed. Error [%d]\n", Error);
	} else {
		TIZEN_LOGD("Smartbonding action success.");
	}
}

static int __invoke_dbus_method_nonblock(const char *dest, const char *path,
		char *interface_name, char *method, GVariant *params,
		GAsyncReadyCallback notify_func)
{
	GDBusConnection *connection;

	TIZEN_LOGD("Sending dbus request");
	connection = _dbus_get_gdbus_conn();
	if (connection == NULL) {
		TIZEN_LOGD("GDBusconnection is NULL!!\n");
		return SMBD_ERR_UNKNOWN;
	}

	g_dbus_connection_call(connection,
				dest,
				path,
				interface_name,
				method,
				params,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				DBUS_REPLY_TIMEOUT,
				_dbus_get_gdbus_cancellable(),
				(GAsyncReadyCallback) notify_func,
				NULL);

	return SMBD_ERR_NONE;
}

static GVariant *__invoke_dbus_method(const char *dest, const char *path,
		char *interface_name, char *method, GVariant *params,
		int *dbus_error)
{
	GError *error = NULL;
	GVariant *reply = NULL;
	*dbus_error = SMBD_ERR_NONE;
	GDBusConnection *connection;

	connection = _dbus_get_gdbus_conn();
	if (connection == NULL) {
		TIZEN_LOGD("GDBusconnection is NULL\n");

		*dbus_error = SMBD_ERR_UNKNOWN;
		return reply;
	}

	reply = g_dbus_connection_call_sync(connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			DBUS_REPLY_TIMEOUT,
			_dbus_get_gdbus_cancellable(),
			&error);
	if (reply == NULL) {
		if (error != NULL) {
			TIZEN_LOGD("g_dbus_connection_call_sync() failed."
					"error [%d: %s]\n",
					error->code, error->message);
			g_error_free(error);
		} else {
			TIZEN_LOGD("g_dbus_connection_call_sync() failed.\n");
		}

		*dbus_error = SMBD_ERR_UNKNOWN;

		return NULL;
	}

	return reply;
}

static int __dbus_create_gdbus_call(void)
{
	GError *error = NULL;

	if (gdbus_conn.connection != NULL) {
		TIZEN_LOGD("Already connection exists");
		return SMBD_ERR_UNKNOWN;
	}

	g_type_init();

	gdbus_conn.connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (gdbus_conn.connection == NULL) {
		TIZEN_LOGD("Failed to connect to the D-BUS daemon: [%s]\n", error->message);
		g_error_free(error);
		return SMBD_ERR_UNKNOWN;
	}

	gdbus_conn.cancellable = g_cancellable_new();

	return SMBD_ERR_NONE;
}

static int __dbus_close_gdbus_call(void)
{
	g_cancellable_cancel(gdbus_conn.cancellable);
	g_object_unref(gdbus_conn.cancellable);
	gdbus_conn.cancellable = NULL;

	if (gdbus_conn.conn_ref_count < 1) {
		/* TODO: Use later. TIZEN_LOGD("There is no pending call\n"); */

		g_object_unref(gdbus_conn.connection);
		gdbus_conn.connection = NULL;
	} else {
		/* TIZEN_LOGD("There are %d pending calls, waiting to be cleared\n",
				gdbus_conn.conn_ref_count); */

		g_object_unref(gdbus_conn.connection);
	}

	return SMBD_ERR_NONE;
}

static void __dbus_smbd_cellular_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	const char *key = NULL;
	gchar *field = NULL;
	gchar *value = NULL;
	GVariant *var = NULL;
	GVariantIter *iter = NULL;

	TIZEN_LOGD("Signal PropertyChanged:cellular_device_info received");
	if (g_strcmp0(sig, SMBD_SIGNAL_PROPERTYCHANGED) == 0) {
		g_variant_get(param, "(sa{ss})", &key, &iter);
		TIZEN_LOGD("signal - [%s] key - [%s]", sig, key);

		if (g_strcmp0(key, SMBD_SIGNAL_VALUE_CELLULAR) == 0) {
			while ((var = g_variant_iter_next_value(iter))) {
				g_variant_get(var, "{ss}", &field, &value);
				SECURE_DB_INFO("field - [%s] value [%s]", field, value);
				if(strncmp(field,"proxy",5) == 0)
					memcpy(smbd_cellular_profile_info.proxy,value,strlen(value));
				else if(strncmp(field,"dns1",4) == 0)
					memcpy(smbd_cellular_profile_info.dns_1,value,strlen(value));
				else if(strncmp(field,"dns2",4) == 0)
					memcpy(smbd_cellular_profile_info.dns_2,value,strlen(value));
				g_free(field);
				g_free(value);
				g_variant_unref(var);
			}

			/* ToDo: Need to send the event */
		}

		g_free((gchar *)key);
	}
}
#if 0
static void __dbus_smbd_wifi_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	const char *key = NULL;
	const char *ipaddr = NULL;
	GVariant *var = NULL;
	GVariantIter *iter;
	smbd_event_info_t event_info = { 0, };

	TIZEN_LOGD("Signal PropertyChanged:wifi_device_info received");
	if (g_strcmp0(sig, SMBD_SIGNAL_PROPERTYCHANGED) == 0) {
		g_variant_get(param, "(sv)", &key, &var);
		TIZEN_LOGD("signal - [%s] key - [%s]", sig, key);

		if (g_strcmp0(key, SMBD_SIGNAL_VALUE_WIFI) == 0) {
			g_variant_get(var, "s", &ipaddr);
			TIZEN_LOGD("value - [%s]", ipaddr);

			TIZEN_LOGD("Sending SMBD_EVENT_WIFI_INFO");

			event_info.Event = SMBD_EVENT_WIFI_INFO;
			event_info.Error = SMBD_ERR_NONE;
			event_info.EventData = (void *)ipaddr;

			if (smartbonding_callbacks.cb != NULL) {
				smartbonding_callbacks.cb(event_info, NULL);
			}

			g_free((gchar *)ipaddr);
		}

		g_free((gchar *)key);
		if (NULL != var)
			g_variant_unref(var);
	}
}
#endif
static void __dbus_smbd_smartbonding_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	const char *key = NULL;
	gboolean smartbonding = FALSE;
	GVariant *var = NULL;
	smbd_event_info_t event_info = { 0, };

	TIZEN_LOGD("Signal PropertyChanged:smartbonding received");
	if (g_strcmp0(sig, SMBD_SIGNAL_PROPERTYCHANGED) == 0) {
		g_variant_get(param, "(sv)", &key, &var);
		TIZEN_LOGD("signal - [%s] key - [%s]", sig, key);

		if (g_strcmp0(key, SMBD_SIGNAL_VALUE_SMARTBONDING) == 0) {
			g_variant_get(var, "b", &smartbonding);
			TIZEN_LOGD("value - [%d]", smartbonding);

			TIZEN_LOGD("Sending SMBD_EVENT_SMARTBONDING_STATUS");

			event_info.Event = SMBD_EVENT_SMARTBONDING_STATUS;
			event_info.Error = SMBD_ERR_NONE;
			event_info.EventData = (void *)smartbonding;

			if (smartbonding_callbacks.cb != NULL) {
				smartbonding_callbacks.cb(event_info, NULL);
			}
		}

		g_free((gchar *)key);
		if (NULL != var)
			g_variant_unref(var);
	}
}

static void __dbus_smbd_user_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	const char *key = NULL;
	gint32 user_option = 0;
	gint32 handle;
	//GVariant *var = NULL;

	TIZEN_LOGD("Signal UserResponse received");
	if (g_strcmp0(sig, SMBD_SIGNAL_USERRESPONSE) == 0) {
		g_variant_get(param, "(s(iu))", &key, &user_option, &handle);
		TIZEN_LOGD("signal - [%s] key - [%s]", sig, key);
		TIZEN_LOGD("user_option - [%d] handle - [%d]", user_option, handle);

		_handle_remove_post_event_send((guint)handle, user_option);

		g_free((gchar *)key);
		//if (NULL != var)
		//	g_variant_unref(var);
	}
}

static int __dbus_register_signal(void)
{
	GDBusConnection *connection = _dbus_get_gdbus_conn();;
	smbd_err_t Error = SMBD_ERR_NONE;

	gdbus_conn_sub_id_smbd_cellular = g_dbus_connection_signal_subscribe(
			connection,
			NULL,
			SMBD_SERVICE_INTERFACE,
			SMBD_SIGNAL_PROPERTYCHANGED,
			NULL,
			SMBD_SIGNAL_VALUE_CELLULAR,
			G_DBUS_SIGNAL_FLAGS_NONE,
			__dbus_smbd_cellular_signal_filter,
			NULL,
			NULL);
#if 0
	gdbus_conn_sub_id_smbd_wifi = g_dbus_connection_signal_subscribe(
			connection,
			NULL,
			SMBD_SERVICE_INTERFACE,
			SMBD_SIGNAL_PROPERTYCHANGED,
			NULL,
			SMBD_SIGNAL_VALUE_WIFI,
			G_DBUS_SIGNAL_FLAGS_NONE,
			__dbus_smbd_wifi_signal_filter,
			NULL,
			NULL);
#endif
	gdbus_conn_sub_id_smbd_smartbonding = g_dbus_connection_signal_subscribe(
			connection,
			NULL,
			SMBD_SERVICE_INTERFACE,
			SMBD_SIGNAL_PROPERTYCHANGED,
			NULL,
			SMBD_SIGNAL_VALUE_SMARTBONDING,
			G_DBUS_SIGNAL_FLAGS_NONE,
			__dbus_smbd_smartbonding_signal_filter,
			NULL,
			NULL);

	gdbus_conn_sub_id_smbd_user = g_dbus_connection_signal_subscribe(
			connection,
			NULL,
			SMBD_SERVICE_INTERFACE,
			SMBD_SIGNAL_USERRESPONSE,
			NULL,
			SMBD_SIGNAL_VALUE_USERRESPONSE,
			G_DBUS_SIGNAL_FLAGS_NONE,
			__dbus_smbd_user_signal_filter,
			NULL,
			NULL);

	if (gdbus_conn_sub_id_smbd_cellular == 0 ||
			//gdbus_conn_sub_id_smbd_wifi == 0 ||
			gdbus_conn_sub_id_smbd_smartbonding == 0 ||
			gdbus_conn_sub_id_smbd_user == 0) {
		TIZEN_LOGD("Failed to register signals smbd cellular id(%d) "
				//"smbd wifi id(%d)
				"smbd smartbonding id(%d) smbd user id(%d)\n",
				gdbus_conn_sub_id_smbd_cellular,
				//gdbus_conn_sub_id_smbd_wifi,
				gdbus_conn_sub_id_smbd_smartbonding,
				gdbus_conn_sub_id_smbd_user);
		Error = SMBD_ERR_UNKNOWN;
	} else {
		TIZEN_LOGD("Signals registered successfully");
	}

	return Error;
}

static int __dbus_deregister_signal(void)
{
	GDBusConnection *connection = _dbus_get_gdbus_conn();
	smbd_err_t Error = SMBD_ERR_NONE;

	if (connection == NULL) {
		TIZEN_LOGD("Connection NULL\n");
		return SMBD_ERR_UNKNOWN;
	}

	g_dbus_connection_signal_unsubscribe(connection,
			gdbus_conn_sub_id_smbd_cellular);
	/* g_dbus_connection_signal_unsubscribe(connection,
			gdbus_conn_sub_id_smbd_wifi); */
	g_dbus_connection_signal_unsubscribe(connection,
			gdbus_conn_sub_id_smbd_smartbonding);
	g_dbus_connection_signal_unsubscribe(connection,
			gdbus_conn_sub_id_smbd_user);

	return Error;
}

int smart_bonding_init(void)
{
	smbd_err_t Error = SMBD_ERR_NONE;

	TIZEN_LOGD("Smartbonding client: Init API");

	Error = __dbus_create_gdbus_call();
	if (Error != SMBD_ERR_NONE) {
		TIZEN_LOGD("Connection creation failed - [%d]\n", Error);
		return Error;
	}

	Error = __dbus_register_signal();
	if (Error != SMBD_ERR_NONE) {
		TIZEN_LOGD("Signal registration failed - [%d]\n", Error);
		return Error;
	}

	return SMBD_ERR_NONE;
}

int smart_bonding_deinit(void)
{
	smbd_err_t Error = SMBD_ERR_NONE;

	TIZEN_LOGD("Smartbonding client: De-init API");

	Error = __dbus_deregister_signal();
	if (Error != SMBD_ERR_NONE) {
		TIZEN_LOGD("Signal de-registration failed - [%d]\n", Error);
		return Error;
	}

	Error = __dbus_close_gdbus_call();
	if (Error != SMBD_ERR_NONE) {
		TIZEN_LOGD("Connection close failed - [%d]\n", Error);
		return Error;
	}

	return SMBD_ERR_NONE;
}

int smart_bonding_start(char *file_name, int file_size,
		smartbonding_cb callback, void *user_data)
{
	smbd_err_t Error = SMBD_ERR_NONE;
	GVariant *params;
	GVariant *msg;
	int smartbonding_value;
	event_info_t *event_info = NULL;
	guint32 handle = 0;

	TIZEN_LOGD("Smartbonding client: Start smartbonding API");
	SECURE_DB_INFO("File - [%s] file size - [%d]", file_name, file_size);

	vconf_get_int(VCONF_SMART_BONDING_POLICY, &smartbonding_value);

	if (smartbonding_value == SMART_BONDING_WIFI_ONLY) {
		TIZEN_LOGD("Smart bonding policy is OFF");
		return SMBD_ERR_POLICY_OFF;
	}

	if (callback == NULL) {
		TIZEN_LOGD("Smart bonding callback not set");
		return SMBD_ERR_INVALID_PARAMETER;
	}

	params = g_variant_new("(su)", file_name, file_size);

	msg = __invoke_dbus_method(SMBD_SERVICE_DBUS, SMBD_PATH_DBUS,
			SMBD_SERVICE_INTERFACE, "StartBonding", params, &Error);
	if (msg == NULL) {
		TIZEN_LOGD("Start smart bonding request failed");

		return Error;
	}

	g_variant_get(msg, "(u)", &handle);
	g_variant_unref(msg);

	if (handle <= 0) {
		TIZEN_LOGD("Start smart bonding request failed."
				" Erroneous handle");
		return SMBD_ERR_UNKNOWN;
	}

	event_info = g_try_new0(event_info_t, 1);
	if (event_info == NULL) {
		TIZEN_LOGD("Start smart bonding request failed."
				"Memory allocation failed");
		return SMBD_ERR_UNKNOWN;
	}
	event_info->cb = callback;
	event_info->user_data = user_data;
	event_info->handle = handle;

	handle_list = g_slist_append(handle_list, event_info);
	TIZEN_LOGD("Added the handle - [%d] into the list", handle);

	TIZEN_LOGD("Start smart bonding request successful");
	return Error;
}

int smart_bonding_stop(void *user_data)
{
	smbd_err_t Error = SMBD_ERR_NONE;
	guint32 handle_id = 0;
	GVariant *params;

	TIZEN_LOGD("Smartbonding client: Stop smartbonding API");

	handle_id = _handle_remove_with_user_data(user_data);

	params = g_variant_new("(u)", handle_id);

	Error = __invoke_dbus_method_nonblock(SMBD_SERVICE_DBUS, SMBD_PATH_DBUS,
			SMBD_SERVICE_INTERFACE, "StopBonding", params, __dbus_reply);
	if (Error != SMBD_ERR_NONE) {
		TIZEN_LOGD("Stop smart bonding request failed");
		return Error;
	}

	TIZEN_LOGD("Stop smart bonding request successful");

	return Error;
}

void smart_bonding_notify_interface_usage(const char *message)
{
	smbd_err_t Error = SMBD_ERR_NONE;
	guint32 handle = 0;
	GVariant *params;
	GVariant *msg;

	params = g_variant_new("(s)", message);

	msg = __invoke_dbus_method(SMBD_SERVICE_DBUS, SMBD_PATH_DBUS,
	SMBD_SERVICE_INTERFACE, "NotifyInterfaceUsage", params, &Error);
	if (msg == NULL) {
		TIZEN_LOGD("Notify smart bonding info failed, Error=%d", Error);
		return;
	}

	g_variant_get(msg, "(u)", &handle);
	g_variant_unref(msg);
	return;
}

