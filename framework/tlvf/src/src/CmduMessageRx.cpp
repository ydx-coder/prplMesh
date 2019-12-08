/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <tlvf/CmduMessageRx.h>
#include <tlvf/CmduParser.h>
#include <tlvf/CmduTlvParser.h>

using namespace ieee1905_1;

CmduMessageRx::CmduMessageRx(uint8_t *buff, size_t buff_len, bool swap) 
    : CmduMessage(buff, buff_len, swap, true), parser(std::make_shared<CmduTlvParser>(*this)) {}

CmduMessageRx::~CmduMessageRx() {}

bool CmduMessageRx::parse(bool swap_needed, bool parse_tlvs)
{
    reset();
    auto cmduhdr = addClass<cCmduHeader>();
    if (!cmduhdr)
        return false;
    
    if (!parse_tlvs)
        return true;

    if (parser->parse())
        return true;
    
    return false;
}
