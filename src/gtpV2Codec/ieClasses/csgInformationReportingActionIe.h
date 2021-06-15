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
#ifndef CSGINFORMATIONREPORTINGACTIONIE_H_
#define CSGINFORMATIONREPORTINGACTIONIE_H_

#include "manual/gtpV2Ie.h"



class CsgInformationReportingActionIe: public GtpV2Ie {
public:
    CsgInformationReportingActionIe();
    virtual ~CsgInformationReportingActionIe();

    bool encodeCsgInformationReportingActionIe(MsgBuffer &buffer,
                 CsgInformationReportingActionIeData const &data);
    bool decodeCsgInformationReportingActionIe(MsgBuffer &buffer,
                 CsgInformationReportingActionIeData &data, Uint16 length);
    void displayCsgInformationReportingActionIe_v(CsgInformationReportingActionIeData const &data,
                 Debug &stream);
};

#endif /* CSGINFORMATIONREPORTINGACTIONIE_H_ */