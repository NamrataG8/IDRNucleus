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
#ifndef TWMIIE_H_
#define TWMIIE_H_

#include "manual/gtpV2Ie.h"



class TwmiIe: public GtpV2Ie {
public:
    TwmiIe();
    virtual ~TwmiIe();

    bool encodeTwmiIe(MsgBuffer &buffer,
                 TwmiIeData const &data);
    bool decodeTwmiIe(MsgBuffer &buffer,
                 TwmiIeData &data, Uint16 length);
    void displayTwmiIe_v(TwmiIeData const &data,
                 Debug &stream);
};

#endif /* TWMIIE_H_ */