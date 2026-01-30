#ifndef GATT_SVR_H
#define GATT_SVR_H

/* Includes */
/* NimBLE GATT APIs */
#include "host/ble_gatt.h"
#include "services/gatt/ble_svc_gatt.h"

/* NimBLE GAP APIs */
#include "host/ble_gap.h"

/* Defines */
#define CMD_CONNECT     0x01u
#define CMD_DISCONNECT  0x02u
#define CMD_SCAN_ONCE   0x03u
#define CMD_SCAN_START  0x04u
#define CMD_SCAN_STOP   0x05u
#define CMD_TCP_START   0x06u
#define CMD_UDP_START   0x07u
#define RESP_WIFI_CONNECTED     0x01u
#define RESP_WIFI_DISCONNECTED  0x02u
#define RESP_WIFI_ACK           0x03u
#define RESP_IP_RECEIVED        0x04u
#define RESP_THROUGHPUT_DONE    0x05u
#define CMD_TYPE_SCANNER 0x01u
#define CMD_TYPE_RSSI    0x02u
#define CMD_TYPE_CTRL    0x03u
#define CMD_TYPE_THR 0x04u

typedef struct {
    uint32_t ipaddr;
    uint16_t port;
    uint8_t duration_sec;
    uint8_t proto;
} sock_throughput_t;

/* Public function declarations */
void send_wifi_scanner_indication(void);
void send_rssi_once(void);
void gatt_svr_disconnect_cb(void);
void gatt_svr_send_wifi_response(uint8_t code);
void send_throughput_response(uint8_t code);
void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg);
bool gatt_svr_is_disconnected();
void gatt_svr_subscribe_cb(struct ble_gap_event *event);
int gatt_svc_init(void);

#endif // GATT_SVR_H
