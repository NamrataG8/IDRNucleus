/*
 * Copyright 2019-present Open Networking Foundation
 * Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __S1AP_MSG_CODES_H_
#define __S1AP_MSG_CODES_H_

/****S1AP Procedude codes****/
#define S1AP_SETUP_REQUEST_CODE 17
#define S1AP_INITIAL_UE_MSG_CODE 12
#define S1AP_UE_CONTEXT_RELEASE_REQUEST_CODE 18
#define S1AP_UE_CONTEXT_RELEASE_CODE 23
#define S1AP_HANDOVER_REQUIRED_CODE 0
#define S1AP_HANDOVER_RESOURCE_ALLOCATION_CODE 1
#define S1AP_HANDOVER_NOTIFY_CODE 2
#define S1AP_ENB_STATUS_TRANSFER_CODE 24
#define S1AP_HANDOVER_CANCEL_CODE 4
#define S1AP_ERAB_SETUP_CODE 5
#define S1AP_ERAB_RELEASE_CODE 7

#define S1AP_ERAB_MODIFICATION_INDICATION_CODE 50

/*uplink NAS Transport*/
#define S1AP_UL_NAS_TX_MSG_CODE 13
#define S1AP_INITIAL_CTX_RESP_CODE 9

/*S1AP Protocol IE types*/
#define S1AP_IE_GLOBAL_ENB_ID 59
#define S1AP_IE_ENB_NAME 60
#define S1AP_IE_SUPPORTED_TAS 64
#define S1AP_IE_DEF_PAGING_DRX 137
#define S1AP_IE_MMENAME 61
#define S1AP_IE_SERVED_GUMMEIES 105
#define S1AP_IE_REL_MME_CAPACITY 87

#define S1AP_IE_MME_UE_ID 0
#define S1AP_IE_CAUSE 2
#define S1AP_IE_ENB_UE_ID 8
#define S1AP_IE_NAS_PDU  26
#define S1AP_IE_TAI  67
#define S1AP_IE_UTRAN_CGI  100
#define S1AP_IE_S_TMSI  96
#define S1AP_IE_RRC_EST_CAUSE  134
#define S1AP_ERAB_SETUP_CTX_SUR 51
#define S1AP_IE_HANDOVER_TYPE  1
#define S1AP_IE_TARGET_ID 4
#define S1AP_IE_SOURCE_TOTARGET_TRANSPARENTCONTAINER	104
#define S1AP_IE_E_RAB_ADMITTED	18
#define S1AP_IE_E_RAB_SETUP_LIST_BEARER_SU_RES 28
#define S1AP_IE_E_RAB_FAILED_TO_SETUP_LIST_BEARER_SU_RES 29
#define S1AP_IE_TARGET_TOSOURCE_TRANSPARENTCONTAINER	123
#define S1AP_IE_ENB_STATUS_TRANSFER_TRANSPARENTCONTAINER	90
#define S1AP_IE_E_RAB_TO_BE_MOD_LIST_BEARER_MOD_IND 199
#define S1AP_IE_E_RAB_RELEASE_LIST_BEARER_REL_COMP 69
#define S1AP_IE_E_RAB_FAILED_TO_RELEASED_LIST 34


#endif /*__S1AP_MSG_CODES*/
