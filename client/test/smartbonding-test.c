/*
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 */

#include <glib.h>
#include <stdio.h>

#include <smartbonding-client.h>

#define FILESIZE 1073741824
static int data = 143;

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data);

static void _smart_bonding_start_cb(smbd_event_info_t event, void *user_data)
{
	printf("Start smart-bonding cb \n");

	switch (event.Event) {
	case SMBD_EVENT_USER_OPTION_OK:
		printf("Event: SMBD_EVENT_USER_OPTION_OK - uid[%d]\n",
				(int) user_data);
		break;
	case SMBD_EVENT_USER_OPTION_CANCEL:
		printf("Event: SMBD_EVENT_USER_OPTION_CANCEL - uid[%d]\n",
				(int) user_data);
		break;
	default:
		break;
	}
}

int test_init_smartbonding(void)
{
	printf("Init smart-bonding\n");
	int ret = smart_bonding_init();
	if (ret != SMBD_ERR_NONE) {
		printf("Init smart-bonding API failed\n");
		return -1;
	}

	printf("Init smart-bonding API success\n");
	return 1;
}

int test_deinit_smartbonding(void)
{
	printf("De-init smart-bonding\n");
	int ret = smart_bonding_deinit();
	if (ret != SMBD_ERR_NONE) {
		printf("De-init smart-bonding API failed\n");
		return -1;
	}

	printf("De-init smart-bonding API success\n");
	return 1;
}

int test_start_smartbonding(void)
{
	printf("Start smart-bonding\n");
	int ret = smart_bonding_start("/filename/test/movie.tar.gz",
			FILESIZE, _smart_bonding_start_cb, (void *)data);
	if (ret != SMBD_ERR_NONE) {
		printf("Start smart-bonding API failed\n");
		if (ret == SMBD_ERR_POLICY_OFF) {
			printf("Feature vconf "
				"(file/private/wifi/network_bonding) is disabled\n");
		} else if (ret == SMBD_ERR_INVALID_PARAMETER) {
			printf("Invalid callback parameter\n");
		}
		return -1;
	}

	printf("Start smart-bonding API success\n");
	return 1;
}

int test_stop_smartbonding(void)
{
	printf("Stop smart-bonding\n");
	int ret = smart_bonding_stop((void *)data);
	if (ret != SMBD_ERR_NONE) {
		printf("Stop smart-bonding API failed\n");
		return -1;
	}

	printf("Stop smart-bonding API success\n");
	return 1;
}


int main(int argc, char **argv)
{
	GMainLoop *mainloop;
	mainloop = g_main_loop_new (NULL, FALSE);

	GIOChannel *channel = g_io_channel_unix_new(0);
	g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL), test_thread, NULL);

	printf("Test Thread created...\n");

	g_main_loop_run (mainloop);

	return 0;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int rv;
	char a[10];

	printf("Event received from stdin\n");

	rv = read(0, a, 10);

	if (rv <= 0 || a[0] == '0') {
		rv = 0;

		rv = test_deinit_smartbonding();
		if (rv == -1)
			printf("Fail to deinitialize.\n");

		exit(1);
	}

	if (a[0] == '\n' || a[0] == '\r') {
		printf("\n\n Smart-bonding API Test App\n\n");
		printf("Options..\n");
		printf("1 	- Initialise smart-bonding\n");
		printf("2 	- Start smart-bonding\n");
		printf("3 	- Stop smart-bonding\n");
		printf("4 	- De-initialise smart-bonding\n");
		printf("0 	- Exit \n");

		printf("ENTER  - Show options menu.......\n");
	}

	switch (a[0]) {
	case '1':
		rv = test_init_smartbonding();
		break;
	case '2':
		rv = test_start_smartbonding();
		break;
	case '3':
		rv = test_stop_smartbonding();
		break;
	case '4':
		rv = test_deinit_smartbonding();
		break;
	default:
		break;
	}

	if (rv == 1)
		printf("Operation successful!\n");
	else
		printf("Operation failed!\n");

	return TRUE;
}

