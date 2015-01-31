#ifndef DECODEHTTP_H_
#define DECODEHTTP_H_

#include "multirat_SB_http.h"

#define MEM_ALLOC(buff,size) \
	 buff = (char*)malloc(size);\
if(NULL == buff) \
{\
	 return -1;\
}\
memset(buff,0,size);\

#define MEM_ALLOC_RET(buff,size) \
	 buff = (char*)malloc(size);\
if(NULL == buff) \
{\
	 return;\
}\
memset(buff,0,size);\

#define DECODE_HTTP_RSP_GET_CONT_LEN(a) a->contLen
#define DECODE_HTTP_RSP_GET_RSP_CODE(a) a->rspcode
#define DECODE_HTTP_RSP_GET_CONT_RNG(a) a->contRange
#define DECODE_HTTP_RSP_GET_CONNECTION(a) a->connection

/**
 * @brief                           initialize HTTP response headers
 * @param[in]         rspHeaders    Response headers
 * @param[in]         len           Length of the response headers
 * @param[in]         dhrsp         structure to store the response
 * @return                          void
 * @retval                          none
 * @retval                          none
 */
void decode_http_rsp_init(int8 *rspHeaders, uint32 len, httpResp *dhrsp);


/**
 * @brief                           returns complete response Length in content Range header
 * @param[in]         contRange     content range
 * @retval                          pointer to content range header value
 * @retval
 * @retval
 */
uint64 decode_http_rsp_get_cont_rnglen(int8 *contRange);

/**
 * @brief                           finds the str string in buf pointer
 * @param[in]           buff        buffer containing string
 * @param[in]           str         string to be found
 * @return                          offset of str if found
 * @retval
 * @retval              -1          not found
 */
int32 decode_http_find_str(int8 *buff, const char *str);

/**
 * @brief                            get the value of HTTP Request header
 * @param[in]           pBuffer      buffer containing HTTP response header
 * @param[in]           pHeaderVal   Pointer for storing HTTP response header value
 * @param[in]           offset       offset of HTTP response header value
 * @return                           success or failure
 * @retval              0            success
 * @retval              -1           failure
 */
int32 decode_http_getvalue(int8 *pBuffer, int8 **pHeaderVal, uint32 offset);

/**
 * @brief                           removes the spaces from header value
 * @param[in]           pBuffer     buffer containing HTTP response header value
 * @param[in]           pHeaderVal  Pointer for storing HTTP response header value
 * @return	                    void
 */
void decode_http_trim(int8 *pBuffer, int8 **pHeaderVal);

/**
 * @brief                           decodes the HTTP request line and stores
 *                                  in psHttpReq strcuture
 * @param[in]           psHttpReq   decoded HTTP request
 * @param[in]           req         buffer contaning HTTP request
 * @return
 * @retval              0           success
 * @retval              -1          failure
 */
int32 decode_req_line(httpReq *psHttpReq, int8 *req);

/**
 * @brief                           decodes the HTTP Request headers
 * @param[in]           psHttpReq   decoded HTTP request
 * @param[in]           headReq     buffer pointing to the HTTP request headers
 * @return
 * @retval
 * @retval
 */
int32 decode_headers(httpReq *psHttpReq, int8 *headReq);

/**
 * @brief                           decodes http request
 * @param[in]           psHttpReq   decoded HTTP Request
 * @param[in]           req         http request
 * @param[in]           reqLen      http request length
 * @return                          decode status
 * @retval              -2          decode failure
 * @retval              0           decode success
 */
int32 decode_http_req(httpReq *psHttpReq);

/**
 * @brief                           process the http response
 * @param[in]           resp        structure storing http response
 * @return
 * @retval              -1          http response decoding error
 * @retval              0           htt response decoding success
 */
int32 process_http_rsp(httpResp *resp);

/**
 * @brief                           delete http request
 * @param[in]           SBData      Smartbonding data
 * @return                          void
 */
void delete_http_req(httpReq *req);

/**
 * @brief                           delete http response
 * @param[in]          SBData       Smartbonding data
 * @return                          void
 */
void delete_http_rsp(httpResp *resp);

#endif /* DECODEHTTPRSP_H_ */

