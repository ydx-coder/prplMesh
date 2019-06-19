///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _TLVF_IEEE_1905_1_TLVWSCM2_H_
#define _TLVF_IEEE_1905_1_TLVWSCM2_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include "tlvf/ieee_1905_1/eTlvType.h"
#include "tlvf/WSC/sM2.h"

namespace ieee1905_1 {


class tlvWscM2 : public BaseClass
{
    public:
        tlvWscM2(uint8_t* buff, size_t buff_len, bool parse = false, bool swap_needed = false);
        tlvWscM2(std::shared_ptr<BaseClass> base, bool parse = false, bool swap_needed = false);
        ~tlvWscM2();

        const eTlvType& type();
        const uint16_t& length();
        WSC::sM2& M2Frame();
        void class_swap();
        static size_t get_initial_size();

    private:
        bool init();
        eTlvType* m_type = nullptr;
        uint16_t* m_length = nullptr;
        WSC::sM2* m_M2Frame = nullptr;
};

}; // close namespace: ieee1905_1

#endif //_TLVF/IEEE_1905_1_TLVWSCM2_H_