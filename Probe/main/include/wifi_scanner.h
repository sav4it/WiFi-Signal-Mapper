#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

#include "esp_wifi.h"

#define MAX_WIFI_CONTINUOUS_SCANNING_TIME_US 300000000ULL

typedef struct {
    uint16_t count; 
    wifi_ap_record_t records[];
} wifi_scan_records_t ;

typedef struct {
    uint8_t ssid_len;
    uint8_t pass_len;
    char ssid[33];
    char pass[65];
} wifi_credentials_t;

typedef enum {
    WIFI_IDLE,
    WIFI_CONNECTING,
    WIFI_CONNECTED,
    WIFI_RSSI_CONTINUOUS,
} wifi_state_t;

typedef enum {
    WIFI_EVT_STA_CONNECTED,
    WIFI_EVT_STA_DISCONNECTED,
    WIFI_EVT_GOT_IP,
    WIFI_EVT_AUTH_FAILED
} wifi_internal_evt_t;

typedef struct {
    wifi_credentials_t creds;
    uint8_t cmd;
} wifi_control_cmd_t;

esp_err_t wifi_scanner_init(void);
wifi_scan_records_t* wifi_scan(); 

#endif
