 /*
 * Copyright 2021-present, Infosys Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __MmContextManager__
#define __MmContextManager__
/******************************************************
* mmContextManager.h
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/blockPoolManager.h.tt>
 ***************************************/
#include "memPoolManager.h"

namespace mme
{
	class MmContext;
	class MmContextManager
	{
		public:
			/****************************************
			* MmContextManager
			*  constructor
			****************************************/
			MmContextManager(int numOfBlocks);
			
			/****************************************
			* MmContextManager
			*    Destructor
			****************************************/
			~MmContextManager();
			
			/******************************************
			 * allocateMmContext
			 * allocate MmContext data block
			 ******************************************/
			MmContext* allocateMmContext();
			
			/******************************************
			 * deallocateMmContext
			 * deallocate a MmContext data block
			 ******************************************/
			void deallocateMmContext(MmContext* MmContextp );
	
		private:
			cmn::memPool::MemPoolManager<MmContext> poolManager_m;
	};
};

#endif
		
		