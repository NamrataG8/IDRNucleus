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
#ifndef PORTNUMBERIE_H_
#define PORTNUMBERIE_H_

#include "manual/gtpV2Ie.h"



class PortNumberIe: public GtpV2Ie {
public:
    PortNumberIe();
    virtual ~PortNumberIe();

    bool encodePortNumberIe(MsgBuffer &buffer,
                 PortNumberIeData const &data);
    bool decodePortNumberIe(MsgBuffer &buffer,
                 PortNumberIeData &data, Uint16 length);
    void displayPortNumberIe_v(PortNumberIeData const &data,
                 Debug &stream);
};

#endif /* PORTNUMBERIE_H_ */