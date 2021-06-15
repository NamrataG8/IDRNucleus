 /*
 * Copyright 2021-present, Infosys Limited.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __UEContextManager__
#define __UEContextManager__
/******************************************************
* uEContextManager.h
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/ctxtManagerTmpls/blockPoolManager.h.tt>
 ***************************************/
#include "memPoolManager.h"

namespace mme
{
	class UEContext;
	class UEContextManager
	{
		public:
			/****************************************
			* UEContextManager
			*  constructor
			****************************************/
			UEContextManager(int numOfBlocks);
			
			/****************************************
			* UEContextManager
			*    Destructor
			****************************************/
			~UEContextManager();
			
			/******************************************
			 * allocateUEContext
			 * allocate UEContext data block
			 ******************************************/
			UEContext* allocateUEContext();
			
			/******************************************
			 * deallocateUEContext
			 * deallocate a UEContext data block
			 ******************************************/
			void deallocateUEContext(UEContext* UEContextp );
	
		private:
			cmn::memPool::MemPoolManager<UEContext> poolManager_m;
	};
};

#endif
		
		
