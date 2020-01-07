/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include "mon_wlan_hal_dwpal.h"

#include <bcl/beerocks_utils.h>
#include <bcl/network/network_utils.h>
#include <bcl/son/son_wireless_utils.h>

#include <easylogging++.h>
#include <net/if.h>

#include <cmath>
#include <functional>

extern "C" {
#include <dwpal.h>
#include <slibc/stdio.h>
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// DWPAL////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace bwl {
namespace dwpal {

//////////////////////////////////////////////////////////////////////////////
////////////////////////// Local Module Definitions //////////////////////////
//////////////////////////////////////////////////////////////////////////////

enum print_ie_type {
    PRINT_SCAN,
    PRINT_LINK,
};

enum ie_type : uint8_t {
    TYPE_SSID                     = 0,
    TYPE_SUPPORTED_RATES          = 1,
    TYPE_TIM                      = 5,
    TYPE_BSS_LOAD                 = 11,
    TYPE_RSN                      = 48,
    TYPE_EXTENDED_SUPPORTED_RATES = 50,
    TYPE_HT_OPERATION             = 61,
    TYPE_VHT_OPERATION            = 192,
    TYPE_VENDOR                   = 221
};

struct ie_printer_t {
    std::string name;
    std::function<void(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)>
        print_func;
    uint8_t minlen;
    uint8_t maxlen;
    uint8_t flags;
};

typedef std::map<uint8_t, ie_printer_t> printers_map;

#define WLAN_CAPABILITY_ESS (1 << 0)
#define WLAN_CAPABILITY_IBSS (1 << 1)
#define WLAN_CAPABILITY_PRIVACY (1 << 4)
#define GET_OP_CLASS(channel) ((channel < 14) ? 4 : 5)

// Allocate a char array wrapped in a shared_ptr
#define ALLOC_SMART_BUFFER(size)                                                                   \
    std::shared_ptr<char>(new char[size], [](char *obj) {                                          \
        if (obj)                                                                                   \
            delete[] obj;                                                                          \
    })

#define HELP_COPY_RET_VOID(x, y)                                                                   \
    {                                                                                              \
        snprintf_s(x, sizeof(x), "%s", y);                                                         \
    }
#define HELP_APPEND_RET_VOID(x, y, z)                                                              \
    {                                                                                              \
        snprintf_s(&x[strnlen_s(x, z)], abs(int(sizeof(x) - strnlen_s(x, z))), "%s,", y);          \
    }

#define HELP_COPY(x, y)                                                                            \
    if (snprintf_s(x, sizeof(x), "%s", y) < 0) {                                                   \
        LOG(ERROR) << "snprintf_s failed";                                                         \
        return false;                                                                              \
    }

#define HELP_APPEND(x, y, z)                                                                       \
    if (snprintf_s(&x[strnlen_s(x, z)], abs(int(sizeof(x) - strnlen_s(x, z))), "%s,", y) < 0) {    \
        LOG(ERROR) << "snprintf_s failed";                                                         \
        return false;                                                                              \
    }

//////////////////////////////////////////////////////////////////////////////
/////////////////////////// Local Module Functions ///////////////////////////
//////////////////////////////////////////////////////////////////////////////

static mon_wlan_hal::Event dwpal_to_bwl_event(const std::string &opcode)
{
    if (opcode == "RRM-CHANNEL-LOAD-RECEIVED") {
        return mon_wlan_hal::Event::RRM_Channel_Load_Response;
    } else if (opcode == "RRM-BEACON-REP-RECEIVED") {
        return mon_wlan_hal::Event::RRM_Beacon_Response;
    } else if (opcode == "RRM-STA-STATISTICS-RECEIVED") {
        return mon_wlan_hal::Event::RRM_STA_Statistics_Response;
    } else if (opcode == "RRM-LINK-MEASUREMENT-RECEIVED") {
        return mon_wlan_hal::Event::RRM_Link_Measurement_Response;
    } else if (opcode == "AP-ENABLED") {
        return mon_wlan_hal::Event::AP_Enabled;
    } else if (opcode == "AP-DISABLED") {
        return mon_wlan_hal::Event::AP_Disabled;
    }

    return mon_wlan_hal::Event::Invalid;
}

static mon_wlan_hal::Event dwpal_nl_to_bwl_event(uint8_t cmd, bool waiting_for_results_ready)
{
    switch (cmd) {
    case NL80211_CMD_TRIGGER_SCAN:
        return mon_wlan_hal::Event::Channel_Scan_Triggered;
    case NL80211_CMD_NEW_SCAN_RESULTS:
        return waiting_for_results_ready ? mon_wlan_hal::Event::Channel_Scan_New_Results_Ready
                                         : mon_wlan_hal::Event::Channel_Scan_Dump_Result;
    case NL80211_CMD_SCAN_ABORTED:
        return mon_wlan_hal::Event::Channel_Scan_Abort;
    case SCAN_FINISH_CB:
        return mon_wlan_hal::Event::Channel_Scan_Finished;
    default:
        LOG(ERROR) << "Unknown event received: " << int(cmd);
        return mon_wlan_hal::Event::Invalid;
    }
}

static void calc_curr_traffic(const uint64_t val, uint64_t &total, uint32_t &curr)
{
    if (val >= total) {
        curr = val - total;
    } else {
        curr = val;
    }
    total = val;
}

static bool dwpal_get_freq(const std::vector<unsigned int> &channel_pool, unsigned int curr_channel,
                           const std::string &iface, ScanParams &scan_params)
{
    int freq_index = 0;
    //configure center frequency for each scanned channel
    for (auto channel : channel_pool) {
        //channel validation
        LOG(DEBUG) << " validating pool channel=" << channel;
        if (son::wireless_utils::which_freq(curr_channel) == beerocks::eFreqType::FREQ_24G) {
            // 2.4G interface
            if (son::wireless_utils::which_freq(channel) == beerocks::eFreqType::FREQ_5G) {
                LOG(ERROR) << " cannot scan 5G channel=" << int(channel)
                           << " on 2G interface=" << iface;
                return false;
            }
        } else {
            // 5G interface
            if (son::wireless_utils::which_freq(channel) == beerocks::eFreqType::FREQ_24G) {
                LOG(ERROR) << " cannot scan 2G channel=" << int(channel)
                           << " on 5G interface=" << iface;
                return false;
            }
        }

        scan_params.freq[freq_index] = beerocks::utils::wifi_channel_to_freq(int(channel));
        LOG(DEBUG) << " channel scan pool add center frequency=" << scan_params.freq[freq_index];
        freq_index++;
    }
    return true;
};

static void mac_addr_n2a(char *mac_addr, unsigned char *arg)
{
    int i, l;

    l = 0;
    for (i = 0; i < ETH_ALEN; i++) {
        if (i == 0) {
            snprintf_s(mac_addr + l, sizeof(mac_addr + l), "%02x", arg[i]);
            l += 2;
        } else {
            snprintf_s(mac_addr + l, sizeof(mac_addr + l), ":%02x", arg[i]);
            l += 3;
        }
    }
}

/********************************
 * Start of printer functions   *
 ********************************/

static void print_ssid(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    std::copy_n(data, len, results.ssid);
}

static void print_supprates(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    if (data == nullptr) {
        return;
    }

    for (int i = 0; i < len; i++) {
        int r = data[i] & 0x7f;

        if (r / 2 == 11) {
            if (!strncmp(results.operating_frequency_band, "2.4GHz", sizeof("2.4GHz") - 1)) {
                HELP_APPEND_RET_VOID(results.supported_standards, "802.11b",
                                     sizeof(results.supported_standards))
                HELP_COPY_RET_VOID(results.operating_standards, "802.11b")
            }
        } else if (r / 2 == 54) {
            if (!strncmp(results.operating_frequency_band, "5GHz", sizeof("5GHz") - 1)) {
                HELP_APPEND_RET_VOID(results.supported_standards, "802.11a",
                                     sizeof(results.supported_standards))
                HELP_COPY_RET_VOID(results.operating_standards, "802.11a")
            }
        }

        char tmp[256] = {'\0'};
        if (0 > snprintf_s(tmp, sizeof(tmp), "%d.%d", r / 2, 5 * (r & 1))) {
            LOG(ERROR) << "snprintf_s failed";
            return;
        }

        if (data[i] & 0x80) {
            HELP_APPEND_RET_VOID(results.basic_data_transfer_rates, tmp,
                                 sizeof(results.basic_data_transfer_rates))
        } else {
            HELP_APPEND_RET_VOID(results.supported_data_transfer_rates, tmp,
                                 sizeof(results.supported_data_transfer_rates))
        }
    }
}

static void print_tim(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    if (data == nullptr) {
        return;
    }

    results.dtim_period = (unsigned int)data[1];
}

static void print_bss_load(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    results.channel_utilization = data[2] / 255;
}

static void print_ht_op(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    (void)len;

    if (data == nullptr) {
        return;
    }

    if (!(data[1] & 0x3)) {
        HELP_COPY_RET_VOID(results.operating_channel_bandwidth, "20MHz")
    } else if ((data[1] & 0x3) != 2) {
        HELP_COPY_RET_VOID(results.operating_channel_bandwidth, "40MHz")
    }

    HELP_APPEND_RET_VOID(results.supported_standards, "802.11n",
                         sizeof(results.supported_standards))
    HELP_COPY_RET_VOID(results.operating_standards, "802.11n")
}

static void print_vht_oper(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    (void)len;

    if (data == nullptr) {
        return;
    }

    switch (data[0]) {
    case 0:
        break;
    case 1:
        if (data[2]) {
            HELP_COPY_RET_VOID(results.operating_channel_bandwidth, "160")
        } else {
            HELP_COPY_RET_VOID(results.operating_channel_bandwidth, "80MHz");
        }
        break;
    case 2:
        HELP_COPY_RET_VOID(results.operating_channel_bandwidth, "80MHz");
        break;
    case 3:
        HELP_COPY_RET_VOID(results.operating_channel_bandwidth, "80+80");
        break;
    default:
        LOG(ERROR) << "illegal";
    }

    if (!strncmp(results.operating_frequency_band, "5GHz", sizeof("5GHz") - 1)) {
        HELP_APPEND_RET_VOID(results.supported_standards, "802.11ac",
                             sizeof(results.supported_standards))
        HELP_COPY_RET_VOID(results.operating_standards, "802.11ac")
    }
}

static void print_rsn(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    (void)len;
    (void)data;

    HELP_APPEND_RET_VOID(results.encryption_mode, "AES", sizeof(results.encryption_mode));
    HELP_APPEND_RET_VOID(results.security_mode_enabled, "WPA2",
                         sizeof(results.security_mode_enabled));
}

static void print_wifi_wpa(const uint8_t *data, uint8_t len, sDcsChannelScanResults &results)
{
    (void)len;
    (void)data;

    HELP_APPEND_RET_VOID(results.encryption_mode, "TKIP", sizeof(results.encryption_mode))
    HELP_APPEND_RET_VOID(results.security_mode_enabled, "WPA",
                         sizeof(results.security_mode_enabled))
}
/********************************
 * End of printer functions   *
 ********************************/

printers_map ie_printers = {
    {ie_type::TYPE_SSID,
     {
         "SSID", print_ssid, 0, 32, BIT(PRINT_SCAN) | BIT(PRINT_LINK),
     }},
    {ie_type::TYPE_SUPPORTED_RATES,
     {
         "Supported rates", print_supprates, 0, 255, BIT(PRINT_SCAN),
     }},
    {ie_type::TYPE_TIM,
     {
         "TIM", print_tim, 4, 255, BIT(PRINT_SCAN),
     }},
    {ie_type::TYPE_BSS_LOAD,
     {
         "BSS Load", print_bss_load, 5, 5, BIT(PRINT_SCAN),
     }},
    {ie_type::TYPE_RSN,
     {
         "RSN", print_rsn, 2, 255, BIT(PRINT_SCAN),
     }},
    {ie_type::TYPE_EXTENDED_SUPPORTED_RATES,
     {
         "Extended supported rates", print_supprates, 0, 255, BIT(PRINT_SCAN),
     }},
    {ie_type::TYPE_HT_OPERATION,
     {
         "HT operation", print_ht_op, 22, 22, BIT(PRINT_SCAN),
     }},
    {ie_type::TYPE_VHT_OPERATION,
     {
         "VHT operation", print_vht_oper, 5, 255, BIT(PRINT_SCAN),
     }}};

printers_map wifi_printers = {{1,
                               {
                                   "WPA", print_wifi_wpa, 2, 255, BIT(PRINT_SCAN),
                               }}};

static void print_vendor(uint8_t len, uint8_t *data)
{
    static const uint8_t ms_oui[3] = {0x00, 0x50, 0xf2};

    if (len < 3) {
        return;
    }

    if (len >= 4 && memcmp(data, ms_oui, 3) == 0) {
        // this function is a stub for extending the support of wifi printers (as defined in iw lib)
        if (wifi_printers.find(data[3]) != wifi_printers.end()) {
            return;
        }
        return;
    }
}

static void print_ie_by_key(const uint8_t key, const uint8_t *data, uint8_t len,
                            sDcsChannelScanResults &results)
{
    auto p = ie_printers.find(key);

    if (p == ie_printers.end()) {
        LOG(ERROR) << "key doesn't exist in map";
        return;
    }

    if (!p->second.print_func) {
        LOG(ERROR) << "print function for key is undefined";
        return;
    }

    if (len < p->second.minlen || len > p->second.maxlen) {
        LOG(ERROR) << "doesn't match min and max len criteria";
        return;
    }

    p->second.print_func(data, len, results);
}

static void print_ies(unsigned char *ie, int ielen, sDcsChannelScanResults &results)
{
    while (ielen >= 2 && ielen >= ie[1]) {
        auto key      = ie[0];
        auto length   = ie[1];
        uint8_t *data = ie + 2;
        if (ie_printers.find(key) != ie_printers.end()) {
            if (key == ie_type::TYPE_EXTENDED_SUPPORTED_RATES) {
                if (!strncmp(results.operating_frequency_band, "2.4GHz", sizeof("2.4GHz") - 1)) {
                    HELP_APPEND_RET_VOID(results.supported_standards, "802.11g",
                                         sizeof(results.supported_standards));
                    HELP_COPY_RET_VOID(results.operating_standards, "802.11g");
                }
            }

            print_ie_by_key(key, (const uint8_t *)data, length, results);
        } else if (ie[0] == ie_type::TYPE_VENDOR /* vendor */) {
            print_vendor(ie[1], data);
        }

        ielen -= length + 2;
        ie += length + 2;
    }
}

static bool read_nl_data_from_msg(struct nlattr **bss, struct nl_msg *msg)
{
    struct genlmsghdr *gnlh = (genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1];

    if (bss == nullptr || msg == nullptr) {
        LOG(ERROR) << "invalid input bss=" << bss << ", msg=" << msg;
        return false;
    }

    bss_policy[NL80211_BSS_BSSID]                = {};
    bss_policy[NL80211_BSS_FREQUENCY].type       = NLA_U32;
    bss_policy[NL80211_BSS_TSF].type             = NLA_U64;
    bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
    bss_policy[NL80211_BSS_CAPABILITY].type      = NLA_U16;
    bss_policy[NL80211_BSS_INFORMATION_ELEMENTS] = {};
    bss_policy[NL80211_BSS_SIGNAL_MBM].type      = NLA_U32;
    bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type   = NLA_U8;
    bss_policy[NL80211_BSS_STATUS].type          = NLA_U32;
    bss_policy[NL80211_BSS_SEEN_MS_AGO].type     = NLA_U32;
    bss_policy[NL80211_BSS_BEACON_IES]           = {};

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS]) {
        LOG(ERROR) << "tb[NL80211_ATTR_BSS] == NULL";
        return false;
    }
    if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy)) {
        LOG(ERROR) << "nla_parse_nested failed";
        return false;
    }
    if (!bss[NL80211_BSS_BSSID]) {
        LOG(ERROR) << "tb[NL80211_BSS_BSSID] == NULL";
        return false;
    }

    return true;
}

static bool translate_nl_data_to_bwl_results(sDcsChannelScanResults &results,
                                             const struct nlattr **bss)
{
    //get bssid
    char mac_addr[MAC_ADDR_SIZE];
    mac_addr_n2a(mac_addr, (unsigned char *)nla_data(bss[NL80211_BSS_BSSID]));
    beerocks::net::network_utils::mac_from_string(results.bssid.oct, mac_addr);

    //get channel and operating frequency band
    if (bss[NL80211_BSS_FREQUENCY]) {
        int freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        if (freq >= 5180) {
            HELP_COPY(results.operating_frequency_band, "5GHz")
        } else {
            HELP_COPY(results.operating_frequency_band, "2.4GHz")
        }
        results.channel = beerocks::utils::wifi_freq_to_channel(freq);
    }

    // get beacon period
    if (bss[NL80211_BSS_BEACON_INTERVAL]) {
        results.beacon_period = (unsigned int)nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]);
    }

    // get signal strength
    if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
        results.signal_strength = (nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC])) / 100;
    } else if (bss[NL80211_BSS_SIGNAL_MBM]) {
        results.signal_strength = (nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM])) / 100;
    }

    //get information elements from information-elements-buffer or from beacon
    if (bss[NL80211_BSS_BEACON_IES]) {
        enum nl80211_bss ies_index = (bss[NL80211_BSS_INFORMATION_ELEMENTS])
                                         ? NL80211_BSS_INFORMATION_ELEMENTS
                                         : NL80211_BSS_BEACON_IES;
        print_ies((unsigned char *)nla_data(bss[ies_index]), nla_len(bss[ies_index]), results);
    }

    //get capabilities: mode, security_mode_enabled
    if (bss[NL80211_BSS_CAPABILITY]) {
        __u16 capa = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);

        if (capa & WLAN_CAPABILITY_IBSS) {
            HELP_COPY(results.mode, "AdHoc")
        } else if (capa & WLAN_CAPABILITY_ESS) {
            HELP_COPY(results.mode, "Infrastructure")
        }

        if (strnlen_s(results.security_mode_enabled, sizeof(results.security_mode_enabled)) == 0) {
            if (capa & WLAN_CAPABILITY_PRIVACY) {
                HELP_COPY(results.security_mode_enabled, "WEP")
            } else {
                HELP_COPY(results.security_mode_enabled, "None")
            }
        }
    }

    return true;
}

static bool get_scan_results_from_nl_msg(sDcsChannelScanResults &results, struct nl_msg *msg)
{
    struct nlattr *bss[NL80211_BSS_MAX + 1];

    if (msg == nullptr) {
        LOG(ERROR) << "invalid input: msg==NULL" << msg;
        return false;
    }

    //prepare
    memset(&results, '\0', sizeof(sDcsChannelScanResults));

    //read msg buffer into nl attributes struct
    if (!read_nl_data_from_msg(bss, msg)) {
        LOG(ERROR) << "failed to read nl data from msg";
        return false;
    }

    if (!translate_nl_data_to_bwl_results(results, (const nlattr **)bss)) {
        LOG(ERROR) << "failed to translate nl data to BWL results";
        return false;
    }

    return true;
}

//////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Implementation ///////////////////////////////
//////////////////////////////////////////////////////////////////////////////

mon_wlan_hal_dwpal::mon_wlan_hal_dwpal(std::string iface_name, hal_event_cb_t callback)
    : base_wlan_hal(bwl::HALType::Monitor, iface_name, IfaceType::Intel, callback),
      base_wlan_hal_dwpal(bwl::HALType::Monitor, iface_name, callback)
{
}

mon_wlan_hal_dwpal::~mon_wlan_hal_dwpal() {}

bool mon_wlan_hal_dwpal::update_radio_stats(SRadioStats &radio_stats)
{
    char *reply = nullptr;

    if (!dwpal_send_cmd("GET_RADIO_INFO", &reply)) {
        LOG(ERROR) << __func__ << " failed";
        return false;
    }

    size_t numOfValidArgs[8] = {0}, replyLen = strnlen(reply, HOSTAPD_TO_DWPAL_MSG_LENGTH);
    uint64_t BytesSent = 0, BytesReceived = 0, PacketsSent = 0, PacketsReceived = 0;
    FieldsToParse fieldsToParse[] = {
        {(void *)&BytesSent, &numOfValidArgs[0], DWPAL_LONG_LONG_INT_PARAM, "BytesSent=", 0},
        {(void *)&BytesReceived, &numOfValidArgs[1], DWPAL_LONG_LONG_INT_PARAM,
         "BytesReceived=", 0},
        {(void *)&PacketsSent, &numOfValidArgs[2], DWPAL_LONG_LONG_INT_PARAM, "PacketsSent=", 0},
        {(void *)&PacketsReceived, &numOfValidArgs[3], DWPAL_LONG_LONG_INT_PARAM,
         "PacketsReceived=", 0},
        {(void *)&radio_stats.bss_load, &numOfValidArgs[4], DWPAL_CHAR_PARAM, "BSS load=", 0},
        {(void *)&radio_stats.errors_sent, &numOfValidArgs[5], DWPAL_INT_PARAM, "ErrorsSent=", 0},
        {(void *)&radio_stats.errors_received, &numOfValidArgs[6], DWPAL_INT_PARAM,
         "ErrorsReceived=", 0},
        {(void *)&radio_stats.noise, &numOfValidArgs[7], DWPAL_CHAR_PARAM, "Noise=", 0},
        /* Must be at the end */
        {NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0}};

    if (dwpal_string_to_struct_parse(reply, replyLen, fieldsToParse, sizeof(SRadioStats)) ==
        DWPAL_FAILURE) {
        LOG(ERROR) << "DWPAL parse error ==> Abort";
        return false;
    }

    /* TEMP: Traces... */
    // LOG(DEBUG) << "GET_RADIO_INFO reply= \n" << reply;
    // LOG(DEBUG) << "numOfValidArgs[0]= " << numOfValidArgs[0] << " BytesSent= " << BytesSent;
    // LOG(DEBUG) << "numOfValidArgs[1]= " << numOfValidArgs[1] << " BytesReceived= " << BytesReceived;
    // LOG(DEBUG) << "numOfValidArgs[2]= " << numOfValidArgs[2] << " PacketsSent= " << PacketsSent;
    // LOG(DEBUG) << "numOfValidArgs[3]= " << numOfValidArgs[3] << " PacketsReceived= " << PacketsReceived;
    // LOG(DEBUG) << "numOfValidArgs[4]= " << numOfValidArgs[4] << " BSS load= " << (int)radio_stats.bss_load;
    // LOG(DEBUG) << "numOfValidArgs[5]= " << numOfValidArgs[5] << " ErrorsSent= " << radio_stats.errors_sent;
    // LOG(DEBUG) << "numOfValidArgs[6]= " << numOfValidArgs[6] << " ErrorsReceived= " << radio_stats.errors_received;
    // LOG(DEBUG) << "numOfValidArgs[7]= " << numOfValidArgs[7] << " Noise= " << (int)radio_stats.noise;
    /* End of TEMP: Traces... */

    for (uint8_t i = 0; i < (sizeof(numOfValidArgs) / sizeof(size_t)); i++) {
        if (numOfValidArgs[i] == 0) {
            LOG(ERROR) << "Failed reading parsed parameter " << (int)i << " ==> Abort";
            return false;
        }
    }

    calc_curr_traffic((uint64_t)BytesSent, radio_stats.tx_bytes_cnt, radio_stats.tx_bytes);
    calc_curr_traffic((uint64_t)BytesReceived, radio_stats.rx_bytes_cnt, radio_stats.rx_bytes);
    calc_curr_traffic((uint64_t)PacketsSent, radio_stats.tx_packets_cnt, radio_stats.tx_packets);
    calc_curr_traffic((uint64_t)PacketsReceived, radio_stats.rx_packets_cnt,
                      radio_stats.rx_packets);

    return true;
}

bool mon_wlan_hal_dwpal::update_vap_stats(const std::string vap_iface_name, SVapStats &vap_stats)
{
    char *reply = nullptr;

    std::string cmd = "GET_VAP_MEASUREMENTS " + vap_iface_name;

    if (!dwpal_send_cmd(cmd, &reply)) {
        LOG(ERROR) << __func__ << " failed";
        return false;
    }

    size_t numOfValidArgs[7] = {0}, replyLen = strnlen(reply, HOSTAPD_TO_DWPAL_MSG_LENGTH);
    uint64_t BytesSent = 0, BytesReceived = 0, PacketsSent = 0, PacketsReceived = 0;
    FieldsToParse fieldsToParse[] = {
        {(void *)&BytesSent, &numOfValidArgs[0], DWPAL_LONG_LONG_INT_PARAM, "BytesSent=", 0},
        {(void *)&BytesReceived, &numOfValidArgs[1], DWPAL_LONG_LONG_INT_PARAM,
         "BytesReceived=", 0},
        {(void *)&PacketsSent, &numOfValidArgs[2], DWPAL_LONG_LONG_INT_PARAM, "PacketsSent=", 0},
        {(void *)&PacketsReceived, &numOfValidArgs[3], DWPAL_LONG_LONG_INT_PARAM,
         "PacketsReceived=", 0},
        {(void *)&vap_stats.retrans_count, &numOfValidArgs[4], DWPAL_INT_PARAM, "RetransCount=", 0},
        {(void *)&vap_stats.errors_sent, &numOfValidArgs[5], DWPAL_INT_PARAM, "ErrorsSent=", 0},
        {(void *)&vap_stats.errors_received, &numOfValidArgs[6], DWPAL_INT_PARAM,
         "ErrorsReceived=", 0},
        /* Must be at the end */
        {NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0}};

    if (dwpal_string_to_struct_parse(reply, replyLen, fieldsToParse, sizeof(SVapStats)) ==
        DWPAL_FAILURE) {
        LOG(ERROR) << "DWPAL parse error ==> Abort";
        return false;
    }

    /* TEMP: Traces... */
    // LOG(DEBUG) << "GET_VAP_MEASUREMENTS reply= \n" << reply;
    // LOG(DEBUG) << "numOfValidArgs[0]= " << numOfValidArgs[0] << " BytesSent= " << BytesSent;
    // LOG(DEBUG) << "numOfValidArgs[1]= " << numOfValidArgs[1] << " BytesReceived= " << BytesReceived;
    // LOG(DEBUG) << "numOfValidArgs[2]= " << numOfValidArgs[2] << " PacketsSent= " << PacketsSent;
    // LOG(DEBUG) << "numOfValidArgs[3]= " << numOfValidArgs[3] << " PacketsReceived= " << PacketsReceived;
    // LOG(DEBUG) << "numOfValidArgs[4]= " << numOfValidArgs[4] << " RetransCount= " << vap_stats.retrans_count;
    // LOG(DEBUG) << "numOfValidArgs[5]= " << numOfValidArgs[5] << " ErrorsSent= " << vap_stats.errors_sent;
    // LOG(DEBUG) << "numOfValidArgs[6]= " << numOfValidArgs[6] << " ErrorsReceived= " << vap_stats.errors_received;
    /* End of TEMP: Traces... */

    for (uint8_t i = 0; i < (sizeof(numOfValidArgs) / sizeof(size_t)); i++) {
        if (numOfValidArgs[i] == 0) {
            LOG(ERROR) << "Failed reading parsed parameter " << (int)i << " ==> Abort";
            return false;
        }
    }

    calc_curr_traffic(BytesSent, vap_stats.tx_bytes_cnt, vap_stats.tx_bytes);
    calc_curr_traffic(BytesReceived, vap_stats.rx_bytes_cnt, vap_stats.rx_bytes);
    calc_curr_traffic(PacketsSent, vap_stats.tx_packets_cnt, vap_stats.tx_packets);
    calc_curr_traffic(PacketsReceived, vap_stats.rx_packets_cnt, vap_stats.rx_packets);

    // TODO: Handle timeouts/deltas externally!
    // auto now = std::chrono::steady_clock::now();
    // auto time_span = std::chrono::duration_cast<std::chrono::milliseconds>(now - vap_stats->last_update_time);
    // vap_stats->delta_ms = float(time_span.count());
    // vap_stats->last_update_time = now;

    return true;
}

bool mon_wlan_hal_dwpal::update_stations_stats(const std::string vap_iface_name,
                                               const std::string sta_mac, SStaStats &sta_stats)
{
    char *reply = nullptr;

    std::string cmd = "GET_STA_MEASUREMENTS " + vap_iface_name + " " + sta_mac;

    if (!dwpal_send_cmd(cmd, &reply)) {
        LOG(ERROR) << __func__ << " failed";
        return false;
    }

    size_t numOfValidArgs[9] = {0}, replyLen = strnlen(reply, HOSTAPD_TO_DWPAL_MSG_LENGTH);
    uint64_t BytesSent = 0, BytesReceived = 0, PacketsSent = 0, PacketsReceived = 0,
             LastDataDownlinkRate = 0, LastDataUplinkRate = 0;
    char ShortTermRSSIAverage[24] = {0};
    char SNR[24]                  = {0};
    FieldsToParse fieldsToParse[] = {
        {(void *)&BytesSent, &numOfValidArgs[0], DWPAL_LONG_LONG_INT_PARAM, "BytesSent=", 0},
        {(void *)&BytesReceived, &numOfValidArgs[1], DWPAL_LONG_LONG_INT_PARAM,
         "BytesReceived=", 0},
        {(void *)&PacketsSent, &numOfValidArgs[2], DWPAL_LONG_LONG_INT_PARAM, "PacketsSent=", 0},
        {(void *)&PacketsReceived, &numOfValidArgs[3], DWPAL_LONG_LONG_INT_PARAM,
         "PacketsReceived=", 0},
        {(void *)&sta_stats.retrans_count, &numOfValidArgs[4], DWPAL_INT_PARAM, "RetransCount=", 0},
        {(void *)ShortTermRSSIAverage, &numOfValidArgs[5], DWPAL_STR_PARAM,
         "ShortTermRSSIAverage=", sizeof(ShortTermRSSIAverage)},
        {(void *)&LastDataDownlinkRate, &numOfValidArgs[6], DWPAL_LONG_LONG_INT_PARAM,
         "LastDataDownlinkRate=", 0},
        {(void *)&LastDataUplinkRate, &numOfValidArgs[7], DWPAL_LONG_LONG_INT_PARAM,
         "LastDataUplinkRate=", 0},
        {(void *)SNR, &numOfValidArgs[8], DWPAL_STR_PARAM, "SNR=", sizeof(SNR)},

        /* Must be at the end */
        {NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0}};

    if (dwpal_string_to_struct_parse(reply, replyLen, fieldsToParse, sizeof(SStaStats)) ==
        DWPAL_FAILURE) {
        LOG(ERROR) << "DWPAL parse error ==> Abort";
        return false;
    }

    /* TEMP: Traces... */
    // LOG(DEBUG) << "GET_STA_MEASUREMENTS reply= \n" << reply;
    // LOG(DEBUG) << "numOfValidArgs[0]= " << numOfValidArgs[0] << " BytesSent= " << BytesSent;
    // LOG(DEBUG) << "numOfValidArgs[1]= " << numOfValidArgs[1] << " BytesReceived= " << BytesReceived;
    // LOG(DEBUG) << "numOfValidArgs[2]= " << numOfValidArgs[2] << " PacketsSent= " << PacketsSent;
    // LOG(DEBUG) << "numOfValidArgs[3]= " << numOfValidArgs[3] << " PacketsReceived= " << PacketsReceived;
    // LOG(DEBUG) << "numOfValidArgs[4]= " << numOfValidArgs[4] << " RetransCount= " << sta_stats.retrans_count;
    // LOG(DEBUG) << "numOfValidArgs[5]= " << numOfValidArgs[5] << " ShortTermRSSIAverage= " << ShortTermRSSIAverage;
    // LOG(DEBUG) << "numOfValidArgs[6]= " << numOfValidArgs[6] << " LastDataDownlinkRate= " << LastDataDownlinkRate;
    // LOG(DEBUG) << "numOfValidArgs[7]= " << numOfValidArgs[7] << " LastDataUplinkRate= " << LastDataUplinkRate;
    // LOG(DEBUG) << "numOfValidArgs[8]= " << numOfValidArgs[8] << " SNR= " << SNR;
    /* End of TEMP: Traces... */

    for (uint8_t i = 0; i < (sizeof(numOfValidArgs) / sizeof(size_t)); i++) {
        if (numOfValidArgs[i] == 0) {
            LOG(ERROR) << "Failed reading parsed parameter " << (int)i << " ==> Abort";
            return false;
        }
    }

    // Format ShortTermRSSIAverage = %d %d %d %d
    auto samples = beerocks::string_utils::str_split(ShortTermRSSIAverage, ' ');
    for (auto &s : samples) {
        float s_float = float(beerocks::string_utils::stoi(s));
        if (s_float > beerocks::RSSI_MIN) {
            sta_stats.rx_rssi_watt += std::pow(10, s_float / float(10));
            sta_stats.rx_rssi_watt_samples_cnt++;
        }
    }

    // Format SNR = %d %d %d %d
    auto samples_snr = beerocks::string_utils::str_split(SNR, ' ');
    for (auto &s : samples_snr) {
        float s_float = float(beerocks::string_utils::stoi(s));
        if (s_float >= beerocks::SNR_MIN) {
            sta_stats.rx_snr_watt += std::pow(10, s_float / float(10));
            sta_stats.rx_snr_watt_samples_cnt++;
        }
    }

    // TODO: Update RSSI externally!
    sta_stats.tx_phy_rate_100kb = (LastDataDownlinkRate / 100);
    sta_stats.rx_phy_rate_100kb = (LastDataUplinkRate / 100);
    calc_curr_traffic(BytesSent, sta_stats.tx_bytes_cnt, sta_stats.tx_bytes);
    calc_curr_traffic(BytesReceived, sta_stats.rx_bytes_cnt, sta_stats.rx_bytes);
    calc_curr_traffic(PacketsSent, sta_stats.tx_packets_cnt, sta_stats.tx_packets);
    calc_curr_traffic(PacketsReceived, sta_stats.rx_packets_cnt, sta_stats.rx_packets);

    return true;
}

bool mon_wlan_hal_dwpal::sta_channel_load_11k_request(const SStaChannelLoadRequest11k &req)
{
    LOG(TRACE) << __func__;

    return true;
}

bool mon_wlan_hal_dwpal::sta_beacon_11k_request(const SBeaconRequest11k &req, int &dialog_token)
{
    LOG(TRACE) << __func__;
    char *reply = nullptr;

    // parameters preperations

    // Mode
    auto request = (!req.enable) ? 0 : req.request;
    auto report  = (!req.enable) ? 0 : req.report;

    uint8_t req_mode = (req.parallel | (req.enable ? 0x02 : 0) | (request ? 0x04 : 0) |
                        (report ? 0x08 : 0) | (req.mandatory_duration ? 0x10 : 0));

    auto op_class = req.op_class < 0 ? GET_OP_CLASS(get_radio_info().channel) : req.op_class;

    std::string measurement_mode;
    switch ((SBeaconRequest11k::MeasurementMode)(req.measurement_mode)) {
    case SBeaconRequest11k::MeasurementMode::Passive:
        measurement_mode = "passive";
        break;
    case SBeaconRequest11k::MeasurementMode::Active:
        measurement_mode = "active";
        break;
    case SBeaconRequest11k::MeasurementMode::Table:
        measurement_mode = "table";
        break;
    default:
        LOG(WARNING) << "Invalid measuremetn mode: " << int(req.measurement_mode)
                     << ", using PASSIVE...";
        measurement_mode = "passive";
    }

    // build command
    std::string cmd = "REQ_BEACON " + beerocks::net::network_utils::mac_to_string(req.sta_mac.oct) +
                      " " +                                 // Destination MAC Address
                      std::to_string(req.repeats) + " " +   // Number of repitions
                      std::to_string(req_mode) + " " +      // Measurements Request Mode
                      std::to_string(op_class) + " " +      // Operating Class
                      std::to_string(req.channel) + " " +   // Channel
                      std::to_string(req.rand_ival) + " " + // Random Interval
                      std::to_string(req.duration) + " " +  // Duration
                      measurement_mode + " " +              // Measurement Mode
                      beerocks::net::network_utils::mac_to_string(req.bssid.oct); // Target BSSID

    /////////////////////////////////////////////////
    //////////////// Optional Fields ////////////////
    /////////////////////////////////////////////////

    // SSID
    if (req.use_optional_ssid) {
        std::string req_ssid = '"' + std::string((char *)req.ssid) + '"';
        cmd += " ssid=" + req_ssid;
    }

    // send command
    if (!dwpal_send_cmd(cmd, &reply)) {
        LOG(ERROR) << __func__ << " failed";
        return false;
    }

    size_t numOfValidArgs[1] = {0}, replyLen = strnlen(reply, HOSTAPD_TO_DWPAL_MSG_LENGTH);
    FieldsToParse fieldsToParse[] = {
        {(void *)&dialog_token, &numOfValidArgs[0], DWPAL_INT_PARAM, "dialog_token=", 0},
        /* Must be at the end */
        {NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0}};

    if (dwpal_string_to_struct_parse(reply, replyLen, fieldsToParse, sizeof(dialog_token)) ==
        DWPAL_FAILURE) {
        LOG(ERROR) << "DWPAL parse error ==> Abort";
        return false;
    }

    /* TEMP: Traces... */
    LOG(DEBUG) << "REQ_BEACON reply= \n" << reply;
    LOG(DEBUG) << "numOfValidArgs[0]= " << numOfValidArgs[0] << " dialog_token= " << dialog_token;
    /* End of TEMP: Traces... */

    for (uint8_t i = 0; i < (sizeof(numOfValidArgs) / sizeof(size_t)); i++) {
        if (numOfValidArgs[i] == 0) {
            LOG(ERROR) << "Failed reading parsed parameter " << (int)i << " ==> Abort";
            return false;
        }
    }

    return true;
}

bool mon_wlan_hal_dwpal::sta_statistics_11k_request(const SStatisticsRequest11k &req)
{
    LOG(TRACE) << __func__;
    return true;
}

bool mon_wlan_hal_dwpal::sta_link_measurements_11k_request(const std::string &sta_mac)
{
    LOG(TRACE) << __func__;
    return true;
}

bool mon_wlan_hal_dwpal::channel_scan_trigger(int dwell_time_msec,
                                              const std::vector<unsigned int> &channel_pool)
{
    LOG(DEBUG) << __func__ << " received on interface=" << m_radio_info.iface_name;

    //build scan parameters
    ScanParams channel_scan_params = {0};
    sScanCfgParams org_fg, new_fg;   //foreground scan param
    sScanCfgParamsBG org_bg, new_bg; //background scan param

    // get original scan params
    if (!dwpal_get_scan_params_fg(org_fg) || !dwpal_get_scan_params_bg(org_bg)) {
        LOG(ERROR) << "Failed getting original scan parameters";
        return false;
    }

    // prepare new scan params with changed dwell time
    memcpy_s(&new_fg, sizeof(new_fg), &org_fg, sizeof(org_fg));
    memcpy_s(&new_bg, sizeof(new_bg), &org_bg, sizeof(org_bg));
    new_fg.passive = dwell_time_msec;
    new_fg.active  = dwell_time_msec;
    new_bg.passive = dwell_time_msec;
    new_bg.active  = dwell_time_msec;

    // set new scan params & get newly set values for validation
    if (!dwpal_set_scan_params_fg(new_fg) || !dwpal_set_scan_params_bg(new_bg)) {
        LOG(ERROR) << "Failed setting new values, restoring original scan parameters";
        dwpal_set_scan_params_fg(org_fg);
        dwpal_set_scan_params_bg(org_bg);
        return false;
    }
    if (!dwpal_get_scan_params_fg(new_fg) || !dwpal_get_scan_params_bg(new_bg) ||
        (new_fg.active != dwell_time_msec) || (new_fg.passive != dwell_time_msec) ||
        (new_bg.active != dwell_time_msec) || (new_bg.passive != dwell_time_msec)) {
        LOG(ERROR) << "Validation failed, restoring original scan parameters";
        dwpal_set_scan_params_fg(org_fg);
        dwpal_set_scan_params_bg(org_bg);
        return false;
    }

    // get frequancies from channel pool and set in scan_params
    if (!dwpal_get_freq(channel_pool, m_radio_info.channel, m_radio_info.iface_name, channel_scan_params)) {
        LOG(ERROR) << "Failed getting frequencies, restoring original scan parameters";
        dwpal_set_scan_params_fg(org_fg);
        dwpal_set_scan_params_bg(org_bg);
        return false;
    }
    LOG(DEBUG) << __func__ << " frequancies set in scan_params";
    // must as single wifi won't allow scan on ap without this flag
    channel_scan_params.ap_force = 1;

    if (dwpal_driver_nl_scan_trigger(get_dwpal_nl_ctx(), (char *)m_radio_info.iface_name.c_str(),
                                     &channel_scan_params) != DWPAL_SUCCESS) {
        LOG(ERROR) << " scan trigger failed! Abort scan, restoring original scan parameters";
        dwpal_set_scan_params_fg(org_fg);
        dwpal_set_scan_params_bg(org_bg);
        return false;
    }

    // timeout for nl confirmation on scan trigger
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // restore scan params with original dwell time
    // no reason to check since we restore the original params here anyway
    // and the next validation will validate the change
    dwpal_set_scan_params_fg(org_fg);
    dwpal_set_scan_params_bg(org_bg);

    // validate if "set" function to original values worked
    if (!dwpal_get_scan_params_fg(new_fg) || !dwpal_get_scan_params_bg(new_bg) ||
        (new_fg.active != org_fg.active) || (new_fg.passive != org_fg.passive) ||
        (new_bg.active != org_bg.active) || (new_bg.passive != org_bg.passive)) {
        LOG(ERROR) << "Validation failed, original scan parameters were not restored";
        return false;
    }

    return true;
}

bool mon_wlan_hal_dwpal::channel_scan_dump_results()
{
    if (!dwpal_nl_cmd_scan_dump()) {
        LOG(ERROR) << " scan results dump failed";
        return false;
    }

    return true;
}

bool mon_wlan_hal_dwpal::process_dwpal_event(char *buffer, int bufLen, const std::string &opcode)
{
    LOG(TRACE) << __func__ << " - opcode: |" << opcode << "|";

    auto event = dwpal_to_bwl_event(opcode);

    // Handle the event
    switch (event) {
    case Event::RRM_Beacon_Response: {
        LOG(DEBUG) << "RRM-BEACON-REP-RECEIVED buffer= \n" << buffer;
        // Allocate response object
        auto resp_buff = ALLOC_SMART_BUFFER(sizeof(SBeaconResponse11k));
        auto resp      = reinterpret_cast<SBeaconResponse11k *>(resp_buff.get());

        if (!resp) {
            LOG(FATAL) << "Memory allocation failed!";
            return false;
        }

        // Initialize the message
        memset(resp_buff.get(), 0, sizeof(SBeaconResponse11k));

        size_t numOfValidArgs[11]      = {0};
        char MACAddress[MAC_ADDR_SIZE] = {0}, bssid[MAC_ADDR_SIZE] = {0};
        FieldsToParse fieldsToParse[] = {
            {NULL /*opCode*/, &numOfValidArgs[0], DWPAL_STR_PARAM, NULL, 0},
            {NULL, &numOfValidArgs[1], DWPAL_STR_PARAM, NULL, 0},
            {(void *)MACAddress, &numOfValidArgs[2], DWPAL_STR_PARAM, NULL, sizeof(MACAddress)},
            {(void *)&resp->channel, &numOfValidArgs[3], DWPAL_CHAR_PARAM, "channel=", 0},
            {(void *)&resp->dialog_token, &numOfValidArgs[4], DWPAL_CHAR_PARAM, "dialog_token=", 0},
            {(void *)&resp->rep_mode, &numOfValidArgs[5], DWPAL_CHAR_PARAM,
             "measurement_rep_mode=", 0},
            {(void *)&resp->op_class, &numOfValidArgs[6], DWPAL_CHAR_PARAM, "op_class=", 0},
            {(void *)&resp->duration, &numOfValidArgs[7], DWPAL_SHORT_INT_PARAM, "duration=", 0},
            {(void *)&resp->rcpi, &numOfValidArgs[8], DWPAL_CHAR_PARAM, "rcpi=", 0},
            {(void *)&resp->rsni, &numOfValidArgs[9], DWPAL_CHAR_PARAM, "rsni=", 0},
            {(void *)bssid, &numOfValidArgs[10], DWPAL_STR_PARAM, "bssid=", sizeof(bssid)},
            /* Must be at the end */
            {NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0}};

        if (dwpal_string_to_struct_parse(buffer, bufLen, fieldsToParse,
                                         sizeof(SBeaconResponse11k)) == DWPAL_FAILURE) {
            LOG(ERROR) << "DWPAL parse error ==> Abort";
            return false;
        }

        /* TEMP: Traces... */
        LOG(DEBUG) << "numOfValidArgs[2]= " << numOfValidArgs[2] << " MACAddress= " << MACAddress;
        LOG(DEBUG) << "numOfValidArgs[3]= " << numOfValidArgs[3]
                   << " channel= " << (int)resp->channel;
        LOG(DEBUG) << "numOfValidArgs[4]= " << numOfValidArgs[4]
                   << " Retransmissions= " << (int)resp->dialog_token;
        LOG(DEBUG) << "numOfValidArgs[5]= " << numOfValidArgs[5]
                   << " measurement_rep_mode= " << (int)resp->rep_mode;
        LOG(DEBUG) << "numOfValidArgs[6]= " << numOfValidArgs[6]
                   << " op_class= " << (int)resp->op_class;
        LOG(DEBUG) << "numOfValidArgs[7]= " << numOfValidArgs[7]
                   << " duration= " << (int)resp->duration;
        LOG(DEBUG) << "numOfValidArgs[8]= " << numOfValidArgs[8] << " rcpi= " << (int)resp->rcpi;
        LOG(DEBUG) << "numOfValidArgs[9]= " << numOfValidArgs[9] << " rsni= " << (int)resp->rsni;
        LOG(DEBUG) << "numOfValidArgs[10]= " << numOfValidArgs[10] << " bssid= " << bssid;
        /* End of TEMP: Traces... */

        for (uint8_t i = 0; i < (sizeof(numOfValidArgs) / sizeof(size_t)); i++) {
            if (numOfValidArgs[i] == 0) {
                LOG(ERROR) << "Failed reading parsed parameter " << (int)i << " ==> Abort";
                return false;
            }
        }

        beerocks::net::network_utils::mac_from_string(resp->sta_mac.oct, MACAddress);
        beerocks::net::network_utils::mac_from_string(resp->bssid.oct, bssid);

        // Add the message to the queue
        event_queue_push(event, resp_buff);
        break;
    }

    case Event::AP_Enabled: {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_ENABLED_NOTIFICATION));
        if (!msg_buff) {
            LOG(FATAL) << "Memory allocation failed!";
            return false;
        }
        auto msg = reinterpret_cast<sHOSTAP_ENABLED_NOTIFICATION *>(msg_buff.get());
        if (!msg) {
            LOG(FATAL) << "Memory allocation failed!";
            return false;
        }

        memset(msg_buff.get(), 0, sizeof(sHOSTAP_ENABLED_NOTIFICATION));
        LOG(DEBUG) << "AP_ENABLED buffer= \n" << buffer;

        char interface[SSID_MAX_SIZE] = {0};
        size_t numOfValidArgs[2]      = {0};
        FieldsToParse fieldsToParse[] = {
            {NULL /*opCode*/, &numOfValidArgs[0], DWPAL_STR_PARAM, NULL, 0},
            {(void *)interface, &numOfValidArgs[1], DWPAL_STR_PARAM, NULL, sizeof(interface)},

            /* Must be at the end */
            {NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0}};

        if (dwpal_string_to_struct_parse(buffer, bufLen, fieldsToParse, sizeof(interface)) ==
            DWPAL_FAILURE) {
            LOG(ERROR) << "DWPAL parse error ==> Abort";
            return false;
        }

        auto iface_ids = beerocks::utils::get_ids_from_iface_string(interface);
        msg->vap_id    = iface_ids.vap_id;

        if (iface_ids.vap_id == beerocks::IFACE_RADIO_ID) {
            // Ignore AP-ENABLED on radio
            return true;
        }

        event_queue_push(event, msg_buff);
        break;
    }

    case Event::AP_Disabled: {
        auto msg_buff = ALLOC_SMART_BUFFER(sizeof(sHOSTAP_DISABLED_NOTIFICATION));
        if (!msg_buff) {
            LOG(FATAL) << "Memory allocation failed!";
            return false;
        }

        auto msg = reinterpret_cast<sHOSTAP_DISABLED_NOTIFICATION *>(msg_buff.get());
        if (!msg) {
            LOG(FATAL) << "Memory allocation failed!";
            return false;
        }

        memset(msg_buff.get(), 0, sizeof(sHOSTAP_DISABLED_NOTIFICATION));
        LOG(INFO) << "AP_Disabled buffer= \n" << buffer;

        char interface[SSID_MAX_SIZE] = {0};
        size_t numOfValidArgs[2]      = {0};
        FieldsToParse fieldsToParse[] = {
            {NULL /*opCode*/, &numOfValidArgs[0], DWPAL_STR_PARAM, NULL, 0},
            {(void *)interface, &numOfValidArgs[1], DWPAL_STR_PARAM, NULL, sizeof(interface)},

            /* Must be at the end */
            {NULL, NULL, DWPAL_NUM_OF_PARSING_TYPES, NULL, 0}};

        if (dwpal_string_to_struct_parse(buffer, bufLen, fieldsToParse, sizeof(interface)) ==
            DWPAL_FAILURE) {
            LOG(ERROR) << "DWPAL parse error ==> Abort";
            return false;
        }

        auto iface_ids = beerocks::utils::get_ids_from_iface_string(interface);
        msg->vap_id    = iface_ids.vap_id;

        event_queue_push(event, msg_buff);
        break;
    }

    case Event::RRM_STA_Statistics_Response:
    case Event::RRM_Link_Measurement_Response:
    case Event::RRM_Channel_Load_Response:
        break;
    // Gracefully ignore unhandled events
    // TODO: Probably should be changed to an error once dwpal will stop
    //       sending empty or irrelevant events...
    default:
        LOG(WARNING) << "Unhandled event received: " << opcode;
        break;
    }

    return true;
}

bool mon_wlan_hal_dwpal::process_dwpal_nl_event(struct nl_msg *msg)
{
    struct nlmsghdr *nlh     = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh  = (genlmsghdr *)nlmsg_data(nlh);
    char ifname[IF_NAMESIZE] = "\0";
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[NL80211_ATTR_IFINDEX] != NULL) {
        if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), ifname);
    }

    auto event = dwpal_nl_to_bwl_event(gnlh->cmd, m_waiting_for_results_ready);

    switch (event) {
    case Event::Channel_Scan_Triggered: {
        LOG(DEBUG) << "DWPAL NL event channel scan triggered";
        if (m_radio_info.iface_name.compare(ifname) != 0) {
            // ifname doesn't match current interface
            // meaning the event was recevied for a diffrent channel
            LOG(DEBUG) << "ignoring event for other interfaces";
            return true;
        }

        m_waiting_for_results_ready = true;
        event_queue_push(event);
        break;
    }
    case Event::Channel_Scan_New_Results_Ready: {
        LOG(DEBUG) << "DWPAL NL event channel scan results dump";
        if (m_radio_info.iface_name.compare(ifname) != 0) {
            // ifname doesn't match current interface
            // meaning the event was recevied for a diffrent channel
            LOG(DEBUG) << "ignoring event for other interfaces";
            return true;
        }

        if (m_nl_seq == 0 && nlh->nlmsg_seq != 0) {
            LOG(DEBUG) << "Results dump are ready with sequence number: " << (int)nlh->nlmsg_seq;
            m_nl_seq                    = nlh->nlmsg_seq;
            m_waiting_for_results_ready = false;
        }

        event_queue_push(event);
        channel_scan_dump_results();
        break;
    }
    case Event::Channel_Scan_Dump_Result: {
        LOG(DEBUG) << "DWPAL NL event channel scan results dump";
        if (m_radio_info.iface_name.compare(ifname) != 0 || nlh->nlmsg_seq != m_nl_seq) {
            // ifname doesn't match current interface or sequence number doesn't match
            // current sequence number meaning the event was recevied for a diffrent channel
            LOG(DEBUG) << "ignoring event for other interfaces";
            return true;
        }

        auto results_buff = ALLOC_SMART_BUFFER(sizeof(sDCS_CHANNEL_SCAN_RESULTS_NOTIFICATION));
        auto results =
            reinterpret_cast<sDCS_CHANNEL_SCAN_RESULTS_NOTIFICATION *>(results_buff.get());
        if (!results) {
            LOG(FATAL) << "Memory allocation failed!";
            return false;
        }
        // Initialize the message
        memset(results_buff.get(), 0, sizeof(sDCS_CHANNEL_SCAN_RESULTS_NOTIFICATION));

        bool parse_results        = !waiting_for_results_ready;
        waiting_for_results_ready = false;

        if (parse_results) {
            if (!get_scan_results_from_nl_msg(results->channel_scan_results, msg)) {
                LOG(ERROR) << "read NL msg to monitor msg failed!";
                return false;
            }
            LOG(DEBUG) << "Processing results for BSSID:"
                       << beerocks::net::network_utils::mac_to_string(results->channel_scan_results.bssid);
        }

        event_queue_push(event,results_buff);
        break;
    }
    case Event::Channel_Scan_Abort: {
        LOG(DEBUG) << "DWPAL NL event channel scan aborted";
        if (m_radio_info.iface_name.compare(ifname) != 0) {
            // ifname doesn't match current interface
            // meaning the event was recevied for a diffrent channel
            LOG(DEBUG) << "ignoring event for other interfaces";
            return true;
        }

        LOG(DEBUG) << "Scan Aborted";

        m_nl_seq                    = 0;
        m_waiting_for_results_ready = false;

        event_queue_push(event);
        break;
    }
    case Event::Channel_Scan_Finished: {
        LOG(DEBUG) << "DWPAL NL event channel scan finished";
        if (nlh->nlmsg_seq != m_nl_seq) {
            // Current event has a sequence number not matching the current sequence number
            // meaning the event was recevied for a diffrent channel
            LOG(DEBUG) << "ignoring event for other interfaces. Got: " << (int)nlh->nlmsg_seq
                       << " instead of: " << (int)m_nl_seq;
            return true;
        }

        LOG(DEBUG) << "Results finished for sequence: " << (int)nlh->nlmsg_seq;

        m_nl_seq                    = 0;
        m_waiting_for_results_ready = false;

        event_queue_push(event);
        break;
    }
    // Gracefully ignore unhandled events
    default:
        LOG(ERROR) << "Unknown DWPAL NL event received: " << int(event);
        break;
    }
    return true;
}

} // namespace dwpal

std::shared_ptr<mon_wlan_hal> mon_wlan_hal_create(std::string iface_name,
                                                  base_wlan_hal::hal_event_cb_t callback)
{
    return std::make_shared<dwpal::mon_wlan_hal_dwpal>(iface_name, callback);
}

} // namespace bwl
