/*
 * Copyright (c) 2019, Infosys Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdproto.h>
#include <freeDiameter/libfdcore.h>

#include "log.h"
#include "err_codes.h"
#include "ipc_api.h"
#include "s6a_fd.h"
#include "s6a.h"
#include "msgType.h"
//#include "detach_stage2_info.h"
#include "hss_message.h"

#define DIAMETER_SUCCESS 2001

/** Global and externs**/
extern struct fd_dict_objects g_fd_dict_objs;
extern struct fd_dict_data g_fd_dict_data;
extern int g_Q_mme_S6a_fd;
/**global and externs end**/



/**
 * @brief callback handler for clr recvd from hss
 * Parse clr, state and do cleanup for freediameter
 * @params callback std
 * @return error/success
 */
static void
parse_idr_subscription_data(struct avp *avp_ptr, idr_Q_msg_t *idr)
{
	struct avp *next = NULL;
	struct avp_hdr *element = NULL;

	CHECK_FCT_DO(fd_msg_avp_hdr(avp_ptr, &element),
                        return);

	if ((NULL == element) ||
           (element->avp_code != g_fd_dict_data.subscription_data.avp_code))
        	return;

	CHECK_FCT_DO(fd_msg_browse(avp_ptr, MSG_BRW_FIRST_CHILD, &next, NULL),
			return);

	for(;
		NULL != next;
		fd_msg_browse(next, MSG_BRW_NEXT, &next, NULL)) {

		fd_msg_avp_hdr (next, &element);

		if(NULL == element) return;

		/*AVP: Access-Restriction-Data(1426)*/
		if(g_fd_dict_data.access_restriction_data.avp_code ==
				element->avp_code) {
			idr->access_restriction_data = element->avp_value->u32;
			continue;
		}

		/*AVP: Subscriber-Status(1424)*/
		if(g_fd_dict_data.subscriber_status.avp_code == element->avp_code) {
			idr->subscription_status = element->avp_value->i32;
			continue;
		}

		/*AVP: Network-Access-Mode(1417)*/
		if(g_fd_dict_data.net_access_mode.avp_code == element->avp_code) {
			idr->net_access_mode = element->avp_value->i32;
			continue;
		}

		/*AVP: Regional-Subscription-Zone-Code(1446)*/
		if(g_fd_dict_data.reg_subs_zone_code.avp_code == element->avp_code) {
			//element->avp_value : 10 string values of len 4
			continue;
		}

		/*AVP: MSISDN(701)*/
		if(g_fd_dict_data.MSISDN.avp_code == element->avp_code) {
			memcpy(idr->MSISDN, element->avp_value->os.data, element->avp_value->os.len);
			continue;
		}


		if(g_fd_dict_data.AMBR.avp_code == element->avp_code) {
			/*AMBR has its own child elements, iterate through those*/
			struct avp *ambr_itr = NULL;
			struct avp_hdr *ambr_element = NULL;

			CHECK_FCT_DO(fd_msg_browse(next, MSG_BRW_FIRST_CHILD,
						&ambr_itr, NULL), return);

			/*Iterate through subscription data child avps*/
			while(NULL != ambr_itr) {
				fd_msg_avp_hdr(ambr_itr, &ambr_element);

				if(g_fd_dict_data.max_req_bandwidth_UL.avp_code ==
						ambr_element->avp_code) {
					idr->max_requested_bw_ul = ambr_element->avp_value->u32;
				}

				if(g_fd_dict_data.max_req_bandwidth_DL.avp_code ==
						ambr_element->avp_code) {
					idr->max_requested_bw_dl = ambr_element->avp_value->u32;
				}

				if(g_fd_dict_data.extended_max_req_bandwidth_UL.avp_code == ambr_element->avp_code) {
                                        idr->extended_max_requested_bw_ul = ambr_element->avp_value->u32;
                                }

				if(g_fd_dict_data.extended_max_req_bandwidth_DL.avp_code == ambr_element->avp_code) {
                                        idr->extended_max_requested_bw_dl = ambr_element->avp_value->u32;
                                }

				CHECK_FCT_DO(fd_msg_browse(ambr_itr, MSG_BRW_NEXT,
						&ambr_itr, NULL), return);
			}
			continue;
		}

		/*AVP: APN-Configuration-Profile(1429)*/
			/*AVP: Context-Identifier(1423)
			AVP: All-APN-Configurations-Included-Indicator(1428)
			AVP: APN-Configuration(1430)*/
		if(g_fd_dict_data.APN_config_profile.avp_code == element->avp_code) {
			/*APN profile has its own child elements, iterate through
			 * those*/
			struct avp *apn_cfg_prof_itr = NULL;
			struct avp_hdr *apn_cfg_prof_element = NULL;

			CHECK_FCT_DO(fd_msg_browse(next, MSG_BRW_FIRST_CHILD,
						&apn_cfg_prof_itr, NULL), return);


			/*Iterate through subscription data child avps*/
			while(NULL != apn_cfg_prof_itr) {
				fd_msg_avp_hdr(apn_cfg_prof_itr, &apn_cfg_prof_element);

				if(g_fd_dict_data.ctx_id.avp_code ==
						apn_cfg_prof_element->avp_code) {
					idr->apn_config_profile_ctx_id =
						apn_cfg_prof_element->avp_value->u32;
				} else
				if(g_fd_dict_data.all_APN_configs_included_ind.avp_code ==
						apn_cfg_prof_element->avp_code) {
					idr->all_APN_cfg_included_ind =
						apn_cfg_prof_element->avp_value->i32;
				} else
				if(g_fd_dict_data.APN_config.avp_code ==
						apn_cfg_prof_element->avp_code){

					//APN configuration list : There is list of elements to read
					struct avp *apn_cfg_itr = NULL;
					struct avp_hdr *apn_cfg_element = NULL;

					CHECK_FCT_DO(fd_msg_browse(apn_cfg_prof_itr,
							MSG_BRW_FIRST_CHILD, &apn_cfg_itr, NULL), return);

					while(NULL != apn_cfg_itr){

						fd_msg_avp_hdr(apn_cfg_itr, &apn_cfg_element);

						// TODO g_fd_dict_data does not have service_slection
						// will finish this part in the following patch
						// service_slection code is 493
						// if(g_fd_dict_data.service_slection ==
						if (493 == apn_cfg_element->avp_code){

							log_msg(LOG_INFO, "APN name recvd from hss - %s",
									apn_cfg_element->avp_value->os.data);
							log_msg(LOG_INFO, "APN length recvd from hss - %lu",
									apn_cfg_element->avp_value->os.len);

							idr->selected_apn.val[0] = apn_cfg_element->avp_value->os.len;
							memcpy(&(idr->selected_apn.val[1]),
									apn_cfg_element->avp_value->os.data,
									apn_cfg_element->avp_value->os.len);
							idr->selected_apn.len =
									apn_cfg_element->avp_value->os.len+1;
						}
						if (848 == apn_cfg_element->avp_code && idr->static_addr == 0){
							struct sockaddr_in  temp;
							int result = fd_dictfct_Address_interpret(apn_cfg_element->avp_value, &temp);
							log_msg(LOG_INFO, "Served IP address found %d %s ", result, inet_ntoa(temp.sin_addr));
							idr->static_addr = temp.sin_addr.s_addr; // network order
						}
						apn_cfg_prof_itr = apn_cfg_itr;

						CHECK_FCT_DO(fd_msg_browse(apn_cfg_itr, MSG_BRW_NEXT,
								&apn_cfg_itr, NULL), return);

					}
					continue;

				}

				CHECK_FCT_DO(fd_msg_browse(apn_cfg_prof_itr, MSG_BRW_NEXT,
						&apn_cfg_prof_itr, NULL), return);
			}
			continue;
		}

		/*AVP: Subscribed-Periodic-RAU-TAU-Timer(1619)*/
		if(g_fd_dict_data.subsc_periodic_RAU_TAU_tmr.avp_code
				== element->avp_code) {
			idr->RAU_TAU_timer = element->avp_value->u32;
			continue;
		}

	}
}

int
idr_resp_callback(struct msg **buf, struct avp *avps, struct session *sess,
			void *data, enum disp_action *action)
{
	struct msg *resp = NULL;
	struct avp *avp_ptr = NULL;
	idr_Q_msg_t idr_msg = {0};
	struct avp_hdr *avp_header = NULL;
	struct avp *avp = NULL;
	unsigned int sess_id_len;
	unsigned char *sess_id= NULL;

	resp = *buf;

	dump_fd_msg(resp);

	/*read session id and extract ue index*/
	CHECK_FCT_DO(fd_sess_getsid(sess, &sess_id, (size_t*)&sess_id_len),
			return S6A_FD_ERROR);
	log_msg(LOG_INFO, "IDR callback ----- >session id=%s ",sess_id);


	CHECK_FCT_DO(fd_msg_browse(*buf, MSG_BRW_FIRST_CHILD, &avp, NULL), return S6A_FD_ERROR);
	while (avp) {
	                struct avp_hdr *hdr = NULL;
	                fd_msg_avp_hdr (avp, &hdr);

	                switch(hdr->avp_code)
	                {
	                    case SUB_DATA_AVP_CODE:
	                    {
	                        parse_idr_subscription_data(avp, &idr_msg);
	                    } break;
	                    default:
	                      goto next;
	                }
	                                next:
	                                    /* Go to next AVP */
	                                    CHECK_FCT_DO(fd_msg_browse(avp, MSG_BRW_NEXT, &avp, NULL), return S6A_FD_ERROR);
	              }
    


	fd_msg_search_avp(resp,g_fd_dict_objs.org_host, &avp_ptr);
	if(NULL != avp_ptr) {
		fd_msg_avp_hdr(avp_ptr, &avp_header);
		memcpy(idr_msg.origin_host,avp_header->avp_value->os.data,sizeof(idr_msg.origin_host));
    }

	fd_msg_search_avp(resp, g_fd_dict_objs.org_realm, &avp_ptr);
	if(NULL != avp_ptr) {
		fd_msg_avp_hdr(avp_ptr, &avp_header);
		memcpy(idr_msg.origin_realm,avp_header->avp_value->os.data,sizeof(idr_msg.origin_realm));
    }
         
	fd_msg_search_avp(resp, g_fd_dict_objs.user_name,&avp_ptr);
	if(NULL != avp_ptr) {
		fd_msg_avp_hdr(avp_ptr, &avp_header);
		memcpy(idr_msg.imsi,avp_header->avp_value->os.data,sizeof(idr_msg.imsi));
    }
       
    /*Insert Subscriber Data Answer Processing*/

    struct msg *ans;

    if (buf == NULL)
        return EINVAL;

    /* Create answer header */
    CHECK_FCT( fd_msg_new_answer_from_req ( fd_g_config->cnf_dict, buf, 0 ) );
    ans = *buf;

    /* Set the Origin-Host, Origin-Realm, Result-Code AVPs */
    CHECK_FCT( fd_msg_rescode_set( ans, "DIAMETER_SUCCESS", NULL, NULL, 1 ) );

    /* Send the answer */
    CHECK_FCT( fd_msg_send( buf, NULL, NULL ) );

    /*Do cleanup for freediameter*/
    fd_msg_free(*buf);

	*buf = NULL;
	
	idr_msg.header.msg_type = insert_subsdata_request;

	idr_msg.header.destInstAddr = htonl(mmeAppInstanceNum_c);
	idr_msg.header.srcInstAddr = htonl(s6AppInstanceNum_c);

	/*Send to stage2 queue*/
    send_tipc_message(g_Q_mme_S6a_fd, mmeAppInstanceNum_c, (char*)&idr_msg, sizeof(idr_Q_msg_t));
	
	return SUCCESS;
}


