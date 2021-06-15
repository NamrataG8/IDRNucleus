 /*
 * Copyright 2021-present, Infosys Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __MmeSvcReqProcedureCtxtManager__
#define __MmeSvcReqProcedureCtxtManager__
/******************************************************
* mmeSvcReqProcedureCtxtManager.h
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/blockPoolManager.h.tt>
 ***************************************/
#include "memPoolManager.h"

namespace mme
{
	class MmeSvcReqProcedureCtxt;
	class MmeSvcReqProcedureCtxtManager
	{
		public:
			/****************************************
			* MmeSvcReqProcedureCtxtManager
			*  constructor
			****************************************/
			MmeSvcReqProcedureCtxtManager(int numOfBlocks);
			
			/****************************************
			* MmeSvcReqProcedureCtxtManager
			*    Destructor
			****************************************/
			~MmeSvcReqProcedureCtxtManager();
			
			/******************************************
			 * allocateMmeSvcReqProcedureCtxt
			 * allocate MmeSvcReqProcedureCtxt data block
			 ******************************************/
			MmeSvcReqProcedureCtxt* allocateMmeSvcReqProcedureCtxt();
			
			/******************************************
			 * deallocateMmeSvcReqProcedureCtxt
			 * deallocate a MmeSvcReqProcedureCtxt data block
			 ******************************************/
			void deallocateMmeSvcReqProcedureCtxt(MmeSvcReqProcedureCtxt* MmeSvcReqProcedureCtxtp );
	
		private:
			cmn::memPool::MemPoolManager<MmeSvcReqProcedureCtxt> poolManager_m;
	};
};

#endif
		
		