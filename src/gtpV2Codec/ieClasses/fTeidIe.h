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
#ifndef FTEIDIE_H_
#define FTEIDIE_H_

#include "manual/gtpV2Ie.h"



class FTeidIe: public GtpV2Ie {
public:
    FTeidIe();
    virtual ~FTeidIe();

    bool encodeFTeidIe(MsgBuffer &buffer,
                 FTeidIeData const &data);
    bool decodeFTeidIe(MsgBuffer &buffer,
                 FTeidIeData &data, Uint16 length);
    void displayFTeidIe_v(FTeidIeData const &data,
                 Debug &stream);
};

#endif /* FTEIDIE_H_ */