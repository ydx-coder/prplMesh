/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BWL_MON_WLAN_HAL_DWPAL_TYPES_H_
#define _BWL_MON_WLAN_HAL_DWPAL_TYPES_H_

namespace bwl {
namespace dwpal {

#define NL_MAX_REPLY_BUFFSIZE 8192
#define NL_ATTR_HDR 4

struct sScanCfgParams {
    int passive;
    int active;
    int num_probe_reqs;
    int probe_reqs_interval;
    int passive_scan_valid_time;
    int active_scan_valid_time;
};

struct sScanCfgParamsBG {
    int passive;
    int active;
    int num_probe_reqs;
    int probe_reqs_interval;
    int num_chans_in_chunk;
    int break_time;
    int break_time_busy;
};

typedef struct {
    char ssid[beerocks::message::WIFI_SSID_MAX_LENGTH];
    sMacAddr bssid;
    char mode[beerocks::message::WIFI_GENERIC_STRING_LENGTH];
    uint32_t channel;
    int32_t signal_strength;
    char security_mode_enabled[beerocks::message::WIFI_GENERIC_STRING_LENGTH];
    char encryption_mode[beerocks::message::WIFI_GENERIC_STRING_LENGTH];
    char operating_frequency_band[beerocks::message::WIFI_OPERATING_STRING_LENGTH];
    char supported_standards[beerocks::message::WIFI_GENERIC_STRING_LENGTH];
    char operating_standards[beerocks::message::WIFI_OPERATING_STRING_LENGTH];
    char operating_channel_bandwidth[beerocks::message::WIFI_OPERATING_STRING_LENGTH];
    uint32_t beacon_period;
    int32_t noise;
    char basic_data_transfer_rates[beerocks::message::WIFI_DATA_TRANSFER_RATES_LIST_LENGTH];
    char supported_data_transfer_rates[beerocks::message::WIFI_DATA_TRANSFER_RATES_LIST_LENGTH];
    uint32_t dtim_period;
    uint32_t channel_utilization;
} sDcsChannelScanResults;

typedef struct {
    sDcsChannelScanResults channel_scan_results;
} sDCS_CHANNEL_SCAN_RESULTS_NOTIFICATION;

} // namespace dwpal
} // namespace bwl

#endif // _BWL_MON_WLAN_HAL_DWPAL_TYPES_H_
