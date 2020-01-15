/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2016-2019 Intel Corporation
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _NODE_H_
#define _NODE_H_

#include "../tasks/task.h"
#include <tlvf/common/sMacAddr.h>
#include <tlvf/ieee_1905_1/tlvReceiverLinkMetric.h>
#include <tlvf/ieee_1905_1/tlvTransmitterLinkMetric.h>
#include <tlvf/wfa_map/tlvApMetric.h>

#include <list>
#include <map>

namespace son {
typedef struct {
    uint8_t channel;
    uint8_t bandwidth;
    int8_t channel_ext_above_secondary;
    std::chrono::steady_clock::time_point csa_exit_timestamp;
    std::chrono::steady_clock::time_point csa_enter_timestamp;
} sWifiChannelRadarStats;

typedef struct {
    std::string mac;
    std::string ssid;
    bool backhaul_vap;
} sVapElement;

// typedef struct {
//     char ssid[beerocks::message::WIFI_SSID_MAX_LENGTH];
//     //The BSSID used for the neighboring WiFi SSID.
//     sMacAddr bssid;
//     //The mode the neighboring WiFi radio is operating in. Enumerate
//     beerocks_message::eChannelScanResultMode mode;
//     //The current radio channel used by the neighboring WiFi radio.
//     uint32_t channel;
//     //An indicator of radio signal strength (RSSI) of the neighboring WiFi radio measured in dBm, as an average of the last 100 packets received.
//     int32_t signal_strength_dBm;
//     //The type of encryption the neighboring WiFi SSID advertises. Enumerate List.
//     beerocks_message::eChannelScanResultSecurityMode security_mode_enabled[beerocks::message::CHANNEL_SCAN_LIST_LENGTH];
//     //The type of encryption the neighboring WiFi SSID advertises. Enumerate List.
//     beerocks_message::eChannelScanResultEncryptionMode encryption_mode[beerocks::message::CHANNEL_SCAN_LIST_LENGTH];
//     //Indicates the frequency band at which the radio this SSID instance is operating. Enumerate
//     beerocks_message::eChannelScanResultOperatingFrequencyBand operating_frequency_band;
//     //List items indicate which IEEE 802.11 standards thisResultinstance can support simultaneously, in the frequency band specified byOperatingFrequencyBand. Enumerate List
//     beerocks_message::eChannelScanResultStandards supported_standards[beerocks::message::CHANNEL_SCAN_LIST_LENGTH];
//     //Indicates which IEEE 802.11 standard that is detected for this Result. Enumerate
//     beerocks_message::eChannelScanResultStandards operating_standards;
//     //Indicates the bandwidth at which the channel is operating. Enumerate
//     beerocks_message::eChannelScanResultChannelBandwidth operating_channel_bandwidth;
//     //Time interval (inms) between transmitting beacons.
//     uint32_t beacon_period_ms;
//     //Indicator of average noise strength (indBm) received from the neighboring WiFi radio.
//     int32_t noise_dBm;
//     //Basic data transmit rates (in Mbps) for the SSID.
//     int16_t basic_data_transfer_rates_mbps[beerocks::message::CHANNEL_SCAN_LIST_LENGTH];
//     //Data transmit rates (in Mbps) for unicast frames at which the SSID will permit a station to connect.
//     int16_t supported_data_transfer_rates_mbps[beerocks::message::CHANNEL_SCAN_LIST_LENGTH];
//     //The number of beacon intervals that elapse between transmission of Beacon frames containing a TIM element whose DTIM count field is 0. This value is transmitted in the DTIM Period field of beacon frames. [802.11-2012]
//     uint32_t dtim_period;
//     //Indicates the fraction of the time AP senses that the channel is in use by the neighboring AP for transmissions.
//     uint32_t channel_utilization;
//     //Timestamp for the channel results
//     std::chrono::steady_clock::time_point timestamp;
// } sChannelScanResultsElement;

class node {
public:
    node(beerocks::eType type_, const std::string mac_);
    bool get_beacon_measurement(std::string ap_mac_, int8_t &rcpi, uint8_t &rsni);
    void set_beacon_measurement(std::string ap_mac_, int8_t rcpi, uint8_t rsni);
    bool get_cross_rx_rssi(std::string ap_mac_, int8_t &rssi, int8_t &rx_packets);
    void set_cross_rx_rssi(std::string ap_mac_, int8_t rssi, int8_t rx_packets);

    void clear_cross_rssi();
    void clear_node_stats_info();
    void clear_hostap_stats_info();

    beerocks::eType get_type();
    bool set_type(beerocks::eType type_);

    int8_t vap_id = beerocks::IFACE_ID_INVALID;
    const std::string mac;           // client
    std::string parent_mac;          // hostap
    std::string previous_parent_mac; //hostap
    std::string radio_identifier;

    std::string ipv4;
    std::string manufacturer;
    int channel = 0;
    std::string name;
    int hierarchy = -1; //redundant but more efficient
    beerocks::message::sRadioCapabilities &capabilities;
    beerocks::message::sRadioCapabilities m_sta_5ghz_capabilities;
    beerocks::message::sRadioCapabilities m_sta_24ghz_capabilities;

    beerocks::eWiFiBandwidth bandwidth = beerocks::BANDWIDTH_160;
    bool channel_ext_above_secondary   = true;

    beerocks::eNodeState state = beerocks::STATE_DISCONNECTED;
    bool handoff               = false;
    bool confined              = false;

    /// Clear this flag when channel switch is not in progress and channel is optimal path.
    /// And run optimal path for clients.
    bool cs_op = false;

    /// Clear this flag when channel switch is not in progress and cs_in_prog_optimal_path flag
    /// is clear too. Run load balancer algo.
    bool cs_lb = false;

    bool supports_5ghz            = true;
    int failed_5ghz_steer_attemps = 0;

    bool supports_24ghz            = true;
    int failed_24ghz_steer_attemps = 0;
    beerocks::eBeaconMeasurementSupportLevel supports_beacon_measurement =
        beerocks::BEACON_MEAS_UNSUPPORTED;
    bool supports_11v            = true;
    int failed_11v_request_count = 0;
    bool operational_state       = false;

    //Used by channel-selection to block the clients from connecting to a hostap
    std::vector<std::string> blocked_hostaps;

    std::chrono::steady_clock::time_point last_state_change;

    int association_handling_task_id             = -1;
    int steering_task_id                         = -1;
    int roaming_task_id                          = -1;
    int load_balancer_task_id                    = -1;
    int client_locating_task_id_new_connection   = -1;
    int client_locating_task_id_exist_connection = -1;

    std::chrono::steady_clock::time_point measurement_sent_timestamp;
    int measurement_recv_delta  = 0;
    int measurement_delay       = 0;
    int measurement_window_size = 60;

    class sta_stats_params {
    public:
        uint32_t rx_packets                             = 0;
        uint32_t tx_packets                             = 0;
        uint32_t rx_bytes                               = 0;
        uint32_t tx_bytes                               = 0;
        uint32_t retrans_count                          = 0;
        uint8_t tx_load_percent                         = 0;
        uint8_t rx_load_percent                         = 0;
        uint16_t rx_phy_rate_100kb                      = 0;
        uint16_t tx_phy_rate_100kb                      = 0;
        int8_t rx_rssi                                  = beerocks::RSSI_INVALID;
        uint16_t stats_delta_ms                         = 0;
        std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
    };
    std::shared_ptr<sta_stats_params> stats_info;

    uint16_t max_supported_phy_rate_100kb = 0;

    uint16_t cross_rx_phy_rate_100kb   = 0;
    uint16_t cross_tx_phy_rate_100kb   = 0;
    double cross_estimated_rx_phy_rate = 0.0;
    double cross_estimated_tx_phy_rate = 0.0;

    int ire_4addr_mode_transition_task_id = 0;
    bool transition_to_4addr_mode         = false;
    bool ire_handoff                      = false;

    class radio {
    public:
        int8_t iface_id           = beerocks::IFACE_ID_INVALID;
        bool active               = false;
        bool is_backhaul_manager  = false;
        bool is_acs_enabled       = false;
        bool enable_repeater_mode = false;
        std::string iface_name;
        beerocks::eIfaceType iface_type;
        std::string driver_version;
        std::vector<beerocks::message::sWifiChannel> supported_channels;
        uint8_t operating_class    = 0;
        int ant_gain               = 0;
        int conducted_power        = 0;
        bool exclude_from_steering = false;
        std::string ssid;
        beerocks::eRadioBandCapability capability = beerocks::SUBBAND_CAPABILITY_UNKNOWN;
        uint16_t vht_center_frequency             = 0;
        int8_t channel_ext_above_primary          = 1;
        bool is_dfs                               = false;
        bool cac_completed                        = false;
        bool on_fail_safe_channel                 = false;
        bool on_sub_band_channel                  = false;
        bool on_dfs_reentry                       = false;
        std::set<std::string> dfs_reentry_clients;
        beerocks::eApActiveMode ap_activity_mode = beerocks::AP_ACTIVE_MODE;

        std::list<sWifiChannelRadarStats> Radar_stats;
        std::vector<uint8_t> conf_restricted_channels;

        class ap_stats_params {
        public:
            int active_sta_count                 = 0;
            uint32_t rx_packets                  = 0;
            uint32_t tx_packets                  = 0;
            uint32_t rx_bytes                    = 0;
            uint32_t tx_bytes                    = 0;
            uint32_t errors_sent                 = 0;
            uint32_t errors_received             = 0;
            uint32_t retrans_count               = 0;
            int8_t noise                         = 0;
            uint8_t channel_load_percent         = 0;
            uint8_t total_client_tx_load_percent = 0;
            uint8_t total_client_rx_load_percent = 0;
            uint16_t stats_delta_ms              = 0;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::shared_ptr<ap_stats_params> stats_info;
        std::unordered_map<int8_t, sVapElement> vaps_info;

        struct channel_scan_config {
            bool is_enabled = false;
            std::set<uint8_t> channel_pool; // default value: empty list
            int interval_sec    = -1;       //-1 (invalid)
            int dwell_time_msec = -1;       //-1 (invalid)
        };

        struct channel_scan_status {
            bool scan_in_progress = false;
            beerocks::eChannelScanErrCode last_scan_error_code =
                beerocks::eChannelScanErrCode::CHANNEL_SCAN_SUCCESS;
        };
        //These members are part of the continuous scan
        //The contiuous scan, scans every
        std::shared_ptr<channel_scan_config> continuous_scan_config;
        std::shared_ptr<channel_scan_status> continuous_scan_status;
        std::list<beerocks_message::sChannelScanResults> continuous_scan_results;

        std::shared_ptr<channel_scan_config> single_scan_config;
        std::shared_ptr<channel_scan_status> single_scan_status;
        std::list<beerocks_message::sChannelScanResults> single_scan_results;
    };
    std::shared_ptr<radio> hostap;

    class link_metrics_data {
    public:
        link_metrics_data(){};
        ~link_metrics_data(){};

        std::vector<ieee1905_1::tlvTransmitterLinkMetric::sInterfacePairInfo>
            transmitterLinkMetrics;
        std::vector<ieee1905_1::tlvReceiverLinkMetric::sInterfacePairInfo> receiverLinkMetrics;

        bool add_transmitter_link_metric(
            std::shared_ptr<ieee1905_1::tlvTransmitterLinkMetric> TxLinkMetricData);
        bool add_receiver_link_metric(
            std::shared_ptr<ieee1905_1::tlvReceiverLinkMetric> RxLinkMetricData);
    };

    class ap_metrics_data {
    public:
        ap_metrics_data(){};
        ~ap_metrics_data(){};

        sMacAddr bssid;
        uint8_t channel_utilization;
        uint16_t number_of_stas_currently_associated;
        std::vector<uint8_t> estimated_service_info_fields;
        bool include_ac_vo = false;
        bool include_ac_bk = false;
        bool include_ac_vi = false;

        bool add_ap_metric_data(std::shared_ptr<wfa_map::tlvApMetric> ApMetricData);
    };

    beerocks::eBandType band_type   = beerocks::eBandType::INVALID_BAND;
    beerocks::eIfaceType iface_type = beerocks::IFACE_TYPE_ETHERNET;
    std::chrono::steady_clock::time_point last_seen;
    std::chrono::steady_clock::time_point last_ping_sent;
    std::chrono::steady_clock::time_point last_ping_received;

    int last_ping_delta_ms   = 0;
    int last_ping_min_ms     = 0;
    int last_ping_max_ms     = 0;
    int last_ping_avg_ms_acc = 0;
    int last_ping_avg_ms     = 0;

    friend std::ostream &operator<<(std::ostream &os, const node &node);
    friend std::ostream &operator<<(std::ostream &os, const node *node);

private:
    class rssi_measurement {
    public:
        rssi_measurement(std::string ap_mac_, int8_t rssi_, int8_t packets_) : ap_mac(ap_mac_)
        {
            rssi      = rssi_;
            packets   = packets_;
            timestamp = std::chrono::steady_clock::now();
        }
        const std::string ap_mac;
        int8_t rssi = beerocks::RSSI_INVALID;
        int8_t packets;
        std::chrono::steady_clock::time_point timestamp;
    };

    class beacon_measurement {
    public:
        beacon_measurement(std::string ap_mac_, int8_t rcpi_, uint8_t rsni_) : ap_mac(ap_mac_)
        {
            rcpi      = rcpi_; // received channel power indication (like rssi)
            rsni      = rsni_; // received signal noise indication (SNR)
            timestamp = std::chrono::steady_clock::now();
        }
        const std::string ap_mac;
        int8_t rcpi  = beerocks::RSSI_INVALID;
        uint8_t rsni = 0;
        std::chrono::steady_clock::time_point timestamp;
    };

    beerocks::eType type;
    std::unordered_map<std::string, std::shared_ptr<beacon_measurement>> beacon_measurements;
    std::unordered_map<std::string, std::shared_ptr<rssi_measurement>> cross_rx_rssi;
};
} // namespace son
#endif
