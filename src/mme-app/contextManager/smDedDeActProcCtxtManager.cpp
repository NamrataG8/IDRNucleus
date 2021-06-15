 /*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */ 
/******************************************************************************
 * smDedDeActProcCtxtManager.cpp
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/blockPoolManager.cpp.tt>
 ******************************************************************************/

#include "memPoolManager.h"
#include "contextManager/dataBlocks.h"
#include "contextManager/smDedDeActProcCtxtManager.h"

using namespace cmn::memPool;

namespace mme
{
	/******************************************************************************
	* Constructor
	******************************************************************************/
	SmDedDeActProcCtxtManager::SmDedDeActProcCtxtManager(int numOfBlocks):poolManager_m(numOfBlocks)
	{
	}
	
	/******************************************************************************
	* Destructor
	******************************************************************************/
	SmDedDeActProcCtxtManager::~SmDedDeActProcCtxtManager()
	{
	}
	
	/******************************************************************************
	* Allocate SmDedDeActProcCtxt data block
	******************************************************************************/
	SmDedDeActProcCtxt* SmDedDeActProcCtxtManager::allocateSmDedDeActProcCtxt()
	{
		SmDedDeActProcCtxt* SmDedDeActProcCtxt_p = poolManager_m.allocate();
		return SmDedDeActProcCtxt_p;
	}
	
	/******************************************************************************
	* Deallocate a SmDedDeActProcCtxt data block
	******************************************************************************/
	void SmDedDeActProcCtxtManager::deallocateSmDedDeActProcCtxt(SmDedDeActProcCtxt* SmDedDeActProcCtxtp )
	{
		poolManager_m.free( SmDedDeActProcCtxtp );
	}
}