

/*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
/**************************************
 * ueInitDetachStates.cpp
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/state.cpp.tt>
 **************************************/


#include "actionTable.h"
#include "actionHandlers/actionHandlers.h"
#include <mmeSmDefs.h>
#include <utils/mmeStatesUtils.h>
#include <utils/mmeTimerTypes.h>

#include "mmeStates/ueInitDetachStates.h"

using namespace mme;
using namespace SM;


/******************************************************************************
* Constructor
******************************************************************************/
DetachStart::DetachStart():State()
{
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
DetachStart::~DetachStart()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
DetachStart* DetachStart::Instance()
{
        static DetachStart state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void DetachStart::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::del_session_req);
                actionTable.addAction(&ActionHandlers::purge_req);
                actionTable.setNextState(DetachWfPurgeRespDelSessionResp::Instance());
                eventToActionsMap[DETACH_REQ_FROM_UE] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::detach_accept_to_ue);
                actionTable.addAction(&ActionHandlers::abort_detach);
                eventToActionsMap[ABORT_EVENT] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t DetachStart::getStateId()const
{
	return detach_start;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* DetachStart::getStateName()const
{
	return "detach_start";
}

/******************************************************************************
* Constructor
******************************************************************************/
DetachWfPurgeRespDelSessionResp::DetachWfPurgeRespDelSessionResp():State()
{
        stateGuardTimeoutDuration_m = defaultStateGuardTimerDuration_c;
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
DetachWfPurgeRespDelSessionResp::~DetachWfPurgeRespDelSessionResp()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
DetachWfPurgeRespDelSessionResp* DetachWfPurgeRespDelSessionResp::Instance()
{
        static DetachWfPurgeRespDelSessionResp state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void DetachWfPurgeRespDelSessionResp::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_del_session_resp);
                actionTable.setNextState(DetachWfPurgeResp::Instance());
                eventToActionsMap[DEL_SESSION_RESP_FROM_SGW] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_pur_resp);
                actionTable.setNextState(DetachWfDelSessionResp::Instance());
                eventToActionsMap[PURGE_RESP_FROM_HSS] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::handle_state_guard_timeouts);
                eventToActionsMap[STATE_GUARD_TIMEOUT] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::handle_s1_rel_req_during_detach);
                eventToActionsMap[S1_REL_REQ_FROM_UE] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::detach_accept_to_ue);
                actionTable.addAction(&ActionHandlers::abort_detach);
                eventToActionsMap[ABORT_EVENT] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t DetachWfPurgeRespDelSessionResp::getStateId()const
{
	return detach_wf_purge_resp_del_session_resp;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* DetachWfPurgeRespDelSessionResp::getStateName()const
{
	return "detach_wf_purge_resp_del_session_resp";
}

/******************************************************************************
* Constructor
******************************************************************************/
DetachWfDelSessionResp::DetachWfDelSessionResp():State()
{
        stateGuardTimeoutDuration_m = defaultStateGuardTimerDuration_c;
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
DetachWfDelSessionResp::~DetachWfDelSessionResp()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
DetachWfDelSessionResp* DetachWfDelSessionResp::Instance()
{
        static DetachWfDelSessionResp state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void DetachWfDelSessionResp::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_del_session_resp);
                actionTable.addAction(&ActionHandlers::detach_accept_to_ue);
                eventToActionsMap[DEL_SESSION_RESP_FROM_SGW] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::handle_state_guard_timeouts);
                eventToActionsMap[STATE_GUARD_TIMEOUT] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::handle_s1_rel_req_during_detach);
                eventToActionsMap[S1_REL_REQ_FROM_UE] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::detach_accept_to_ue);
                actionTable.addAction(&ActionHandlers::abort_detach);
                eventToActionsMap[ABORT_EVENT] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t DetachWfDelSessionResp::getStateId()const
{
	return detach_wf_del_session_resp;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* DetachWfDelSessionResp::getStateName()const
{
	return "detach_wf_del_session_resp";
}

/******************************************************************************
* Constructor
******************************************************************************/
DetachWfPurgeResp::DetachWfPurgeResp():State()
{
        stateGuardTimeoutDuration_m = defaultStateGuardTimerDuration_c;
        stateEntryAction = &MmeStatesUtils::on_state_entry;
        stateExitAction = &MmeStatesUtils::on_state_exit;
        eventValidator = &MmeStatesUtils::validate_event;
		
}

/******************************************************************************
* Destructor
******************************************************************************/
DetachWfPurgeResp::~DetachWfPurgeResp()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
DetachWfPurgeResp* DetachWfPurgeResp::Instance()
{
        static DetachWfPurgeResp state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void DetachWfPurgeResp::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_pur_resp);
                actionTable.addAction(&ActionHandlers::detach_accept_to_ue);
                eventToActionsMap[PURGE_RESP_FROM_HSS] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::handle_state_guard_timeouts);
                eventToActionsMap[STATE_GUARD_TIMEOUT] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::handle_s1_rel_req_during_detach);
                eventToActionsMap[S1_REL_REQ_FROM_UE] = actionTable;
        }
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::detach_accept_to_ue);
                actionTable.addAction(&ActionHandlers::abort_detach);
                eventToActionsMap[ABORT_EVENT] = actionTable;
        }
}

/******************************************************************************
* returns stateId
******************************************************************************/
uint16_t DetachWfPurgeResp::getStateId()const
{
	return detach_wf_purge_resp;
}

/******************************************************************************
* returns stateName
******************************************************************************/
const char* DetachWfPurgeResp::getStateName()const
{
	return "detach_wf_purge_resp";
}
