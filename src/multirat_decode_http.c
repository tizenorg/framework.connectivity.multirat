#include "multirat_decode_http.h"

void decode_http_rsp_init(int8 *rspHeaders, uint32 len, httpResp *dhrsp)
{
	memcpy(dhrsp->resp_buff, rspHeaders, len);
	dhrsp->resp_buff[len] = '\0';
	dhrsp->http  = NULL;
	dhrsp->rspcode  = NULL;
	dhrsp->connection  = NULL;
	dhrsp->contLen  = NULL;
	dhrsp->contRange  = NULL;
	dhrsp->accept_range  = NULL;
}

int32 decode_http_getvalue(int8 *pBuffer, int8 **pHeaderVal, uint32 offset)
{
	int32 pos = 0;
	int8 *tempVal = NULL;

	pos = decode_http_find_str(pBuffer, END_OF_LINE);
	if (pos == -1)
	{
		return -1;
	}

	MEM_ALLOC(tempVal, (pos -offset + 1));
	memcpy(tempVal, pBuffer + offset, pos -offset);
	tempVal[pos -offset] = '\0';
	decode_http_trim(tempVal, pHeaderVal);

	free(tempVal);
	tempVal = NULL;
	return (pos + 2);
}/* End of getValue() */

void decode_http_trim(int8 *pBuffer, int8 **pHeaderVal)
{
	uint32 i = 0;
	uint32 leftSpace = 0;
	uint32 rightSpace = 0;
	uint32 actualLen = 0;
	uint32 buffLen = strlen(pBuffer);
	int8 *tempBuf = NULL;

	for (i = 0; i < buffLen ; i++)
	{
		if (pBuffer[i] == ' ')
		{
			leftSpace++;
		}
		else
		{
			break;
		}
	}
	for( i = (buffLen -1); i > 0; i--)
	{
		if (pBuffer[i] == ' ')
		{
			rightSpace++;
		}
		else
		{
			break;
		}
	}

	actualLen = buffLen -leftSpace -rightSpace;
	MEM_ALLOC_RET(*pHeaderVal, (actualLen + 1));
	tempBuf = *pHeaderVal;
	memcpy(tempBuf, pBuffer + leftSpace, actualLen);
	tempBuf[actualLen]  = '\0';

	return;
}/* End of trim() */

int32 decode_http_find_str(int8 *buff, const char *str)
{
	const char *pTemp = NULL;

	if (buff && str )
	{
		pTemp = strstr((const char*)buff, (const char*)str);
		if (pTemp)
		{
			return (int)(pTemp - buff);
		}
	}
	return -1;
}


uint64 decode_http_rsp_get_cont_rnglen(int8 *contRange)
{
	int32 pos = 0;
	uint64 retval = 0;
	int8 tempVal[MAX_CONT_LEN] = {0};

	pos = decode_http_find_str(contRange, "/");
	if ((-1 != pos) && (NULL != strstr(contRange, "bytes")))
	{
		strncpy(tempVal, (contRange + (pos + 1)),strlen(contRange) -pos);
		retval = atol(tempVal);
	}
	return retval;
}/* End of getContRngLen() */

int32 process_http_rsp(httpResp *resp)
{
	int32 len = 0;
	int32 retval = HTTP_RSP_DECODING_ERROR;
	int8 *tempBuff = resp->resp_buff;

	if ( (-1 != decode_http_find_str(tempBuff, "HTTP")))
		/* to check whether the http version is HTTP 1.1*/
	{
		MEM_ALLOC(resp->http, 9);
		strncpy(resp->http, tempBuff, 8);
		tempBuff = tempBuff + 9;
		len = decode_http_find_str(tempBuff, "\r\n");
		if (-1 != len)
		{
			MEM_ALLOC(resp->rspcode, (len + 1));
			memcpy(resp->rspcode, tempBuff, len);
			resp->rspcode[len] = '\0';
			tempBuff = tempBuff + len + 2;
			TIZEN_D_LOGD("resp code [%s]",resp->rspcode);
		}
	}
	else
	{
		return retval;
	}

	while (1)
	{
		len = 0;
		if ((strlen(tempBuff) == LEN_OF_CRLF) && strncmp(tempBuff, END_OF_LINE, LEN_OF_CRLF) == 0)
		{
			retval = HTTP_RSP_DECODING_SUCCESS;
			break;
		}
		if (strncmp(CONNECTION_RSP_HEADER, tempBuff,LEN_CONNECTION_RSP_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuff,&(resp->connection),
					LEN_CONNECTION_RSP_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding connection header");
				break;
			}
			tempBuff = tempBuff + len;
		}
		else if (strncmp(CONTRANGE_RSP_HEADER, tempBuff, LEN_CONTRANGE_RSP_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuff,&resp->contRange,LEN_CONTRANGE_RSP_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Content len header");
				break;
			}
			tempBuff = tempBuff + len;
		}
		else if (strncmp(LOCATION_RSP_HEADER, tempBuff,  LEN_LOCATION_RSP_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuff, &resp->location, LEN_LOCATION_RSP_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Location Header");
				break;
			}

			tempBuff = tempBuff + len;
		}

		else if (strncmp(CONTLEN_RSP_HEADER, tempBuff,LEN_CONTLEN_RSP_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuff,&resp->contLen,LEN_CONTLEN_RSP_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Content len header");
				break;
			}
			resp->cLen = atol(resp->contLen);
			tempBuff = tempBuff + len;
		}
		else if (strncmp(ACCEPT_RANGE_REQ_HEADER, tempBuff, LEN_ACCEPT_RANGE_REQ_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuff,&resp->accept_range,LEN_ACCEPT_RANGE_REQ_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Accept Range header");
				break;
			}
			if((resp->accept_range != NULL) && (0 == strcasecmp(resp->accept_range,"none")))
			{
				resp->acceptFlag = 0;
			}
			else
			{
				resp->acceptFlag = 1;
			}
			tempBuff = tempBuff + len;
		}
		else
		{
			len = decode_http_find_str(tempBuff, END_OF_LINE);
			if (len == -1)
			{
				TIZEN_LOGD("invalid header string length [%d] [%s]",strlen(tempBuff), tempBuff);
				break;
			}
			else
			{
				tempBuff = tempBuff + len+ 2;
			}
		}
	}
	if(resp->accept_range == NULL)
	{
		/* If Accept Range Field is not present in HTTP Response It means Range is Supported */
		/* Only When it is Present as Accept-Ranges: none then only it is not supported */
		resp->acceptFlag = 1;
	}
	if (((0 == strncasecmp(resp->rspcode,"302",strlen("302"))) ||
			(0 == strncasecmp(resp->rspcode,"301",
					strlen("301"))) ||
					(0 == strncasecmp(resp->rspcode,"300",
					strlen("300"))) ||
					(0 == strncasecmp(resp->rspcode,"303",
					strlen("303")))) && (retval == HTTP_RSP_DECODING_SUCCESS))
	{
		retval = HTTP_RSP_REDIRECT;
	}/* End of else */
	TIZEN_D_LOGD("return value process http [%d]", retval);
	return retval;
}/* End of process_http_rsp */

int32 decode_req_line(httpReq *psHttpReq, int8 *req)
{
	int8 *pTempBuff = req;
	int len_method = 0;
	int len_version = 0;
	int len = 0;
	/* Type of Method */
	if ((len_method = decode_http_find_str(pTempBuff, "GET")) != -1)
	{
		psHttpReq->method = HTTP_GET;
		pTempBuff = pTempBuff + 4;
		len_method = len_method + 4;
	}
	else if ((len_method = decode_http_find_str(pTempBuff, "POST")) != -1)
	{
		psHttpReq->method = HTTP_POST;
		pTempBuff = pTempBuff + 5;
		len_method = len_method + 5;
	}
	else if ((len_method = decode_http_find_str(pTempBuff, "HEAD")) != -1)
	{
		psHttpReq->method = HTTP_HEAD;
		pTempBuff = pTempBuff + 5;
		len_method = len_method + 5;
	}
	else
	{
		TIZEN_LOGD("Error !!! HTTP method is unknown [%s]", psHttpReq->method);
		return -1;
	}
	TIZEN_D_LOGD("Method Lenght [%d]", len_method);


/*
	// HTTP Version
	if((len_version = decode_http_find_str(pTempBuff, "HTTP")) != -1)
	{
		psHttpReq->version = HTTP_VERSION_1_0;
	}
	else if((len_version = decode_http_find_str(pTempBuff, "HTTP")) != -1)
	{
		psHttpReq->version = HTTP_VERSION_1_1;
	}
	else
	{
		TIZEN_LOGD("Error !!! HTTP version is unknown [%s]", psHttpReq->version);
		return -1;
	}
*/

	len_version = decode_http_find_str(pTempBuff, "HTTP");

	TIZEN_D_LOGD("Version Length [%d]",len_version);

	pTempBuff = pTempBuff + len_version + 10;


	/*PREVENT FIX */
	if(len_version >= 0 )
	{

		len = len_version;

		MEM_ALLOC(psHttpReq->url, len);
		memcpy(psHttpReq->url, req + len_method, len - 1);

		SECURE_DB_INFO("URL: [%s]", psHttpReq->url, len);
	}

	return (int)(pTempBuff - req);
}/* End of decode_req_line() */

int32 decode_headers(httpReq *psHttpReq, int8 *headReq)
{
	int8 *tempBuf = headReq;
	int32 len = 0;
	int32 retval;

	while (1)
	{
		retval  = HTTP_RSP_DECODING_ERROR;
		len = 0;
		if ((strlen(tempBuf) == LEN_OF_CRLF) &&	strncmp(tempBuf, END_OF_LINE, LEN_OF_CRLF) == 0)
		{
			retval = HTTP_RSP_DECODING_SUCCESS;
			break;
		}

		if (strncasecmp(CONNECTION_REQ_HEADER, tempBuf, LEN_CONNECTION_REQ_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuf,&psHttpReq->connection,
					LEN_CONNECTION_REQ_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding connection header");
				break;
			}
			tempBuf = tempBuf + len;
		}
		else if (strncasecmp(ACCEPT_RANGE_REQ_HEADER, tempBuf,LEN_ACCEPT_RANGE_REQ_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuf,&psHttpReq->accept_range,
					LEN_ACCEPT_RANGE_REQ_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Accept header");
				break;
			}
			tempBuf = tempBuf + len;

		}
		else if (strncasecmp(CONTLEN_REQ_HEADER, tempBuf,LEN_CONTLEN_REQ_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuf, &psHttpReq->contLen,
					LEN_CONTLEN_REQ_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Content len header");
				break;
			}
			tempBuf =  tempBuf + len;

		}
		else if (strncasecmp(RANGELEN_REQ_HEADER_CMP1, tempBuf, LEN_RANGELEN_REQ_HEADER_CMP1) == 0)
		{
			if ((len = decode_http_getvalue(tempBuf, &psHttpReq->Rangeheader,
					LEN_RANGELEN_REQ_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Range len header");
				break;
			}
			tempBuf = tempBuf + len;

		}
		else if(strncasecmp(RANGELEN_REQ_HEADER_CMP2, tempBuf, LEN_RANGELEN_REQ_HEADER_CMP2) == 0)
		{
			if ((len = decode_http_getvalue(tempBuf, &psHttpReq->Rangeheader,
					LEN_RANGELEN_REQ_HEADER)) == -1)
			{
				TIZEN_LOGD("Error !!! in decoding Range len header");
				break;
			}
			tempBuf = tempBuf + len;

		}

		else if (strncasecmp(CONTYPE_REQ_HEADER, tempBuf, LEN_CONTYPE_REQ_HEADER) == 0)
		{
			if ((len = decode_http_getvalue(tempBuf, &psHttpReq->contType,
					LEN_CONTYPE_REQ_HEADER)) == -1)
			{
				TIZEN_LOGD("Error in decoding Content type header");
				break;
			}
			tempBuf = tempBuf + len;
			TIZEN_LOGD("Content-Type: [%s]", psHttpReq->contType);
		}

		else if (strncasecmp(IF_RANGE, tempBuf, LEN_IF_RANGE) == 0)
		{
			if ((len = decode_http_getvalue(tempBuf, &psHttpReq->ifRange,
					LEN_IF_RANGE)) == -1)
			{
				TIZEN_LOGD("Error in decoding If Range Header");
				break;
			}
			tempBuf = tempBuf + len;
			TIZEN_LOGD("If-Range: [%s]", psHttpReq->ifRange);
		}
		else
		{
			len = decode_http_find_str(tempBuf, END_OF_LINE);
			if (len == -1)
			{
				printf("invalid Header");
				break;
			}
			else
			{
				tempBuf = tempBuf + len + 2;
			}
		}
	}/* End of while */
	return retval;
}/* End of decode_headers() */

int32 decode_http_req(httpReq *psHttpReq)
{
	int32 len = 0;
	int32 retval = HTTP_RSP_DECODING_ERROR;
	int8 *pTempBuff = psHttpReq->req_buff;
	int8 *headReq = NULL;

	len = decode_req_line(psHttpReq, pTempBuff);
	if(len < 0)
	{
		TIZEN_LOGD("Error !!! Decoding Request Line failed");
		return retval;;
	}
	pTempBuff = pTempBuff + len;

	len = decode_http_find_str(pTempBuff,END_OF_HEADERS);
	if(len > 0)
	{
		/* End of headers found */
		MEM_ALLOC(headReq,(len+5));
		memcpy(headReq,pTempBuff,len+4);
		headReq[len+4]='\0';
		retval = decode_headers(psHttpReq,headReq);
		free(headReq);
		headReq = NULL;
		pTempBuff = pTempBuff + len + 4;
	}/* End of if */
	return retval;
}/* End of decode_http_req */

void delete_http_rsp(httpResp *dhrsp)
{
	if(NULL != dhrsp->connection)
	{
		free(dhrsp->connection);
	}
	if(NULL != dhrsp->contLen)
	{
		free(dhrsp->contLen);
	}
	if(NULL != dhrsp->rspcode)
	{
		free(dhrsp->rspcode);
	}
	if(NULL != dhrsp->contRange)
	{
		free(dhrsp->contRange);
	}
	if(NULL != dhrsp->location)
	{
		free(dhrsp->location);
	}
	if(NULL != dhrsp->http)
	{
		free(dhrsp->http);
	}
	if(NULL != dhrsp->accept_range)
	{
		free(dhrsp->accept_range);
	}

	dhrsp->connection = NULL;
	dhrsp->contLen = NULL;
	dhrsp->rspcode = NULL;
	dhrsp->contRange =  NULL;
	dhrsp->http = NULL;
	dhrsp->location = NULL;
	dhrsp->accept_range = NULL;
}

void delete_http_req(httpReq *req)
{
	if(req->url != NULL)
	{
		free(req->url);
		req->url = NULL;
	}
	if(req->accept_range != NULL)
	{
		free(req->accept_range);
		req->accept_range = NULL;
	}
	if(req->connection != NULL)
	{
		free(req->connection);
		req->connection = NULL;
	}
	if(req->contLen != NULL)
	{
		free(req->contLen);
		req->contLen = NULL;
	}
	if(req->Rangeheader != NULL)
	{
		free(req->Rangeheader);
		req->Rangeheader =  NULL;
	}
	if(req->contType != NULL)
	{
		free(req->contType);
		req->contType = NULL;
	}
	if(req->ifRange != NULL)
	{
		free(req->ifRange);
		req->ifRange = NULL;
	}
	if(req->req_buff != NULL)
	{
		free(req->req_buff);
		req->req_buff = NULL;
	}
	if(req->req_buff_wo_range != NULL)
	{
		free(req->req_buff_wo_range);
		req->req_buff_wo_range = NULL;
	}
	if(req->request[0] != NULL)
	{
		free(req->request[0]);
		req->request[0] =  NULL;
	}
	if(req->request[1] != NULL)
	{
		free(req->request[1]);
		req->request[1] =  NULL;
	}
}

