/*
 * Copyright 2019-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/******************************************************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/ietemplate.cpp.tt>
 ******************************************************************************/

#include "counterIe.h"
#include "dataTypeCodecUtils.h"

CounterIe::CounterIe() 
{
    ieType = 199;
    // TODO

}

CounterIe::~CounterIe() {
    // TODO Auto-generated destructor stub
}

bool CounterIe::encodeCounterIe(MsgBuffer &buffer, CounterIeData const &data)
{
    if (!(buffer.writeUint32(data.timeStampValue)))
    {
        errorStream.add((char *)"Encoding of timeStampValue failed\n");
        return false;
    }
    if (!(buffer.writeUint8(data.counterValue)))
    {
        errorStream.add((char *)"Encoding of counterValue failed\n");
        return false;
    }

    return true;
}

bool CounterIe::decodeCounterIe(MsgBuffer &buffer, CounterIeData &data, Uint16 length)
{     
    // TODO optimize the length checks
    
    Uint16 ieBoundary = buffer.getCurrentIndex() + length;

    buffer.readUint32(data.timeStampValue);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: timeStampValue\n");
        return false;
    }

    buffer.readUint8(data.counterValue);
    if (buffer.getCurrentIndex() > ieBoundary)
    {
        errorStream.add((char *)"Attempt to read beyond IE boundary: counterValue\n");
        return false;
    }

    // The IE is decoded now. The buffer index should be pointing to the 
    // IE Boundary. If not, we have some more data left for the IE which we don't know
    // how to decode
    if (ieBoundary == buffer.getCurrentIndex())
    {
        return true;
    }
    else
    {
        errorStream.add((char *)"Unable to decode IE CounterIe\n");
        return false;
    }
}
void CounterIe::displayCounterIe_v(CounterIeData const &data, Debug &stream)
{
    stream.incrIndent();
    stream.add((char *)"CounterIeData:");
    stream.incrIndent();
    stream.endOfLine();
  
    stream.add((char *)"timeStampValue: ");
    stream.add(data.timeStampValue);
    stream.endOfLine();
  
    stream.add((char *)"counterValue: ");
    stream.add(data.counterValue);
    stream.endOfLine();
    stream.decrIndent();
    stream.decrIndent();
}
