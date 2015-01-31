#include "multirat_conf.h"
#include "multirat_SB_http.h"
#include "multirat_libapi.h"
#ifdef TIZEN_UX_SUPPORT
#include "smartbonding-client.h"
#endif

#include <glib.h>

#ifdef TIZEN_UX_SUPPORT
static int Lib_Init = SMBD_ERR_INVALID_PARAMETER;
#endif


#ifdef TIZEN_UX_SUPPORT
uint32 lib_init_success(void)
{
	if(Lib_Init != SMBD_ERR_NONE)
	{
		return 0;
	}
	else
		return 1;
}

uint32 smartbonding_client_init(void)
{
	if(lib_init_success() != 1)
	{
		Lib_Init = smart_bonding_init();
		if (Lib_Init != SMBD_ERR_NONE) {
			TIZEN_LOGD("Smart Bonding Client Library Init Failed");
			return 0;
		}
		else{
			TIZEN_LOGD("Smart Bonding Client Library Init Success");
			return 1;
		}
	}
	return 1;
}
#endif

int32 get_multirat_threshold()
{
	return MULTIRAT_SIZE_THRESHOLD;
}


int32 get_multirat_temp_threshold()
{
	return  MULTIRAT_TEMP_THRESHOLD;
}

