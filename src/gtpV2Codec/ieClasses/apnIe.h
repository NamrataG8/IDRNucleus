/*
 * Copyright (c) 2020, Infosys Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 /******************************************************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/ietemplate.h.tt>
 ******************************************************************************/
#ifndef APNIE_H_
#define APNIE_H_

#include "manual/gtpV2Ie.h"



class ApnIe: public GtpV2Ie {
public:
    ApnIe();
    virtual ~ApnIe();

    bool encodeApnIe(MsgBuffer &buffer,
                 ApnIeData const &data);
    bool decodeApnIe(MsgBuffer &buffer,
                 ApnIeData &data, Uint16 length);
    void displayApnIe_v(ApnIeData const &data,
                 Debug &stream);
};

#endif /* APNIE_H_ */