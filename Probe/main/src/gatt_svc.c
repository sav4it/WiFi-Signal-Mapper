#include "gatt_svc.h"
#include "common.h"
#include "esp_log.h"
#include "freertos/idf_additions.h"
#include "host/ble_att.h"
#include "host/ble_gatt.h"
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_uuid.h"
#include "lwip/sockets.h"
#include "wifi_scanner.h"

#define MAX_BLE_PAYLOAD 244
#define MIN(x, y) ((x) < (y) ? (x) : (y))

// TODO make all connections encrypted and pair the esp once on the client side

/* Private function declarations */
static int wifi_scan_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg);
static int wifi_rssi_chr_access(uint16_t conn_handle, uint16_t attr_handle, 
                            struct ble_gatt_access_ctxt *ctxt, void *arg);
static int wifi_control_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg);
static int throughput_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg);

/* extern variables */
extern QueueHandle_t scan_cmd_queue;
extern QueueHandle_t wifi_rssi_cmd_queue;
extern QueueHandle_t control_cmd_queue;
extern QueueHandle_t throughput_cmd_queue;

/* Private variables */
/* UUIDs */
static const ble_uuid128_t wifi_scanner_svc_uuid    = BLE_UUID128_INIT(0x91, 0x40, 0xb4, 0x9e, 0x62, 0x18, 0x46, 0xc7, 0x92, 0xba, 0x6c, 0xf4, 0xae, 0xf2, 0x1f, 0xab);
static const ble_uuid128_t wifi_scanner_chr_uuid    = BLE_UUID128_INIT(0x54, 0xf8, 0xfd, 0xf1, 0x49, 0x2f, 0x49, 0x9b, 0xbd, 0x18, 0xed, 0x61, 0x70, 0xaf, 0x93, 0x0b);
static const ble_uuid128_t wifi_rssi_chr_uuid       = BLE_UUID128_INIT(0xf8, 0x72, 0x2f, 0xc6, 0xff, 0xb7, 0x49, 0xb8, 0xa1, 0xc3, 0x64, 0xf2, 0xa5, 0x7a, 0x10, 0xd3);
static const ble_uuid128_t wifi_control_chr_uuid    = BLE_UUID128_INIT(0xbc, 0xc9, 0x42, 0x4f, 0x31, 0x95, 0x4b, 0x28, 0xad, 0xa5, 0x8f, 0x95, 0x3e, 0x4e, 0x76, 0x52);
static const ble_uuid128_t throughput_chr_uuid  = BLE_UUID128_INIT(0x67, 0xc7, 0x1a, 0xb7, 0x04, 0xfe, 0x4d, 0x82,0xac, 0xf6, 0x3f, 0x16, 0xd5, 0xec, 0x04, 0xe8);
/* characteristic handles */
static uint16_t wifi_scan_chr_val_handle;
static uint16_t wifi_rssi_chr_val_handle;
static uint16_t wifi_control_chr_val_handle;
static uint16_t throughput_chr_val_handle;

static uint16_t ble_conn_handle = BLE_HS_CONN_HANDLE_NONE;

/* notify flags */
static bool wifi_scanner_notify_enabled     = false;
static bool wifi_rssi_notify_enabled        = false;
static bool wifi_control_notify_enabled     = false;
static bool throughput_notify_enabled   = false;

/* GATT services table */
static const struct ble_gatt_svc_def gatt_svr_svcs[] = {
    /* Wifi */
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &wifi_scanner_svc_uuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[]){ /* wifi scanner */
                                        {.uuid = &wifi_scanner_chr_uuid.u,
                                         .access_cb = wifi_scan_chr_access,
                                         .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY,
                                         .val_handle = &wifi_scan_chr_val_handle 
                                        }, 
                                        { /* wifi rssi retriever*/
                                        .uuid = &wifi_rssi_chr_uuid.u,
                                        .access_cb = wifi_rssi_chr_access,
                                        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY,
                                        .val_handle = &wifi_rssi_chr_val_handle 
                                        },
                                        { /* wifi control signal manager */
                                        .uuid = &wifi_control_chr_uuid.u,
                                        .access_cb = &wifi_control_chr_access,
                                        .flags = BLE_GATT_CHR_F_WRITE |
                                                 BLE_GATT_CHR_F_WRITE_ENC |
                                                 BLE_GATT_CHR_F_NOTIFY,
                                        .val_handle = &wifi_control_chr_val_handle
                                        },
                                        {
                                        .uuid = &throughput_chr_uuid.u,
                                        .access_cb = &throughput_chr_access,
                                        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_NOTIFY,
                                        .val_handle = &throughput_chr_val_handle
                                        },{0}},
    },
    {
        0, /* No more services. */
    },
};

/* Private functions */
/* Access callbacks */
static int wifi_scan_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                                 struct ble_gatt_access_ctxt *ctxt, void *arg) {

    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) 
        return BLE_ATT_ERR_UNLIKELY;
      
    const uint8_t *data = ctxt->om->om_data;
    int len = ctxt->om->om_len;

    // [cmd_type:1][cmd:1]
    if (len != 2) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    if (data[0] != CMD_TYPE_SCANNER) return BLE_ATT_ERR_UNLIKELY;

    uint8_t cmd = data[1];
    switch (cmd) {
        case CMD_SCAN_ONCE:
        case CMD_SCAN_START:
        case CMD_SCAN_STOP:
            xQueueSend(scan_cmd_queue, &cmd, 0);
            break;
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }
    return 0;
}

static int wifi_rssi_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {

    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;

    const uint8_t *data = ctxt->om->om_data;
    int len = ctxt->om->om_len;

    // [cmd_type:1][cmd:1]
    if (len != 2) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    if (data[0] != CMD_TYPE_RSSI) return BLE_ATT_ERR_UNLIKELY;

    uint8_t cmd_type = data[1];
    switch(cmd_type) {
        case CMD_SCAN_ONCE:
        case CMD_SCAN_START:
        case CMD_SCAN_STOP:
            xQueueSend(wifi_rssi_cmd_queue, &cmd_type, 0);
            break;
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }

    return 0;
}

static int wifi_control_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;

    // Check if the link is encrypted
    struct ble_gap_conn_desc desc;
    int rc = ble_gap_conn_find(conn_handle, &desc);
    if (rc || !desc.sec_state.encrypted)
        return BLE_ATT_ERR_INSUFFICIENT_ENC;

    const uint8_t *data = ctxt->om->om_data;
    int len = ctxt->om->om_len;

    // Data format: [cmd_type:1][cmd:1][opt:[ssid_len:1][ssid:1-32][pass_len:1][pass:1-64]]
    if (len < 2) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    if (data[0] != CMD_TYPE_CTRL) return BLE_ATT_ERR_UNLIKELY;

    uint8_t cmd = data[1];
    wifi_control_cmd_t msg = {0};
    switch(cmd) {
        case CMD_CONNECT: {
            if (len < 4) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;

            // get ssid 
            msg.creds.ssid_len = data[2];
            if (len < 4 + msg.creds.ssid_len || msg.creds.ssid_len > 32) 
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            memcpy(msg.creds.ssid, &data[3], msg.creds.ssid_len);
            msg.creds.ssid[msg.creds.ssid_len] = '\0';

            // get password
            msg.creds.pass_len = data[3 + msg.creds.ssid_len];
            if (len < 4 + msg.creds.ssid_len + msg.creds.pass_len || msg.creds.pass_len > 64) 
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            memcpy(msg.creds.pass, &data[4 + msg.creds.ssid_len], msg.creds.pass_len);
            msg.creds.pass[msg.creds.pass_len] = '\0';

            msg.cmd = CMD_CONNECT;
            if (xQueueSend(control_cmd_queue, &msg, 0) != pdTRUE)
                return BLE_ATT_ERR_UNLIKELY;

            break;
        }
        case CMD_DISCONNECT:
            msg.cmd = cmd;
            xQueueSend(control_cmd_queue, &msg, 0); 
            break;
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }

    return 0;
}

static int throughput_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {

    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;
    ESP_LOGI(TAG, "throughput char entered");
    const uint8_t *data = ctxt->om->om_data;
    int len = ctxt->om->om_len;

    // Data format: [cmd_type:1][cmd:1][ipv4:4][port:2][duration,sec:1]
    if (len != 9) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    if (data[0] != CMD_TYPE_THR) return BLE_ATT_ERR_UNLIKELY;
    ESP_LOGI(TAG, "correct packet format");

    uint8_t cmd = data[1];
    sock_throughput_t cfg = {0};
    switch (cmd) {
    case CMD_TCP_START:
        memcpy(&cfg.ipaddr,  &data[2], 4);
        memcpy(&cfg.port,&data[6], 2);
        memcpy(&cfg.duration_sec, &data[8], 1);
        cfg.proto = IPPROTO_TCP;
        ESP_LOGI(TAG, "tcp recognized");
        if (xQueueSend(throughput_cmd_queue, &cfg, 0) != pdTRUE)
            return BLE_ATT_ERR_UNLIKELY;
        ESP_LOGI(TAG, "tcp command sent to the queue");
        break;
    case CMD_UDP_START:
        memcpy(&cfg.ipaddr,  &data[2], 4);
        memcpy(&cfg.port,&data[6], 2);
        memcpy(&cfg.duration_sec, &data[8], 1);
        cfg.proto = IPPROTO_UDP;
        ESP_LOGI(TAG, "udp recognized");
        if (xQueueSend(throughput_cmd_queue, &cfg, 0) != pdTRUE)
            return BLE_ATT_ERR_UNLIKELY;
        ESP_LOGI(TAG, "udp command sent to the queue");
        break;
    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
    ESP_LOGI(TAG, "successfully exiting throughput_chr");

    return 0;
}

/* Notify functions */
static void send_wifi_packets(wifi_scan_records_t* records) {
    if (!records || records->count == 0) {
        return;
    }

    uint16_t mtu = ble_att_mtu(ble_conn_handle);
    if(mtu < 3) return;
    uint16_t max_payload = mtu - 3;
    ESP_LOGI(TAG, "MTU=%d", max_payload);

    uint8_t data[MAX_BLE_PAYLOAD];

    uint16_t i = 0;
    while (i < records->count) {
        uint16_t offset = 0;

        while (i < records->count) {
            const wifi_ap_record_t *rec = &records->records[i];
            uint8_t ssid_len = strnlen((char*)rec->ssid, 32);

            /* Per-record size: len + ssid + rssi */
            uint16_t record_len = 1 + ssid_len + 1;

            /* If this record does not fit in current packet, send packet */
            if (offset + record_len > max_payload) {
                break;
            }

            /* Pack record */
            data[offset++] = ssid_len;
            memcpy(&data[offset], rec->ssid, ssid_len);
            offset += ssid_len;
            data[offset++] = (uint8_t)rec->rssi;

            i++;
        }

        /* Send packet */
        if (offset > 0) {
            struct os_mbuf *om;

            om = ble_hs_mbuf_from_flat(data, offset);
            if (!om) {
            // handle allocation failure
            return;
            }   
            int rc = ble_gatts_notify_custom(ble_conn_handle,
                             wifi_scan_chr_val_handle,
                             om);

            if (rc != 0) {
                os_mbuf_free_chain(om);
                break; 
            }
            /* Yield a bit to avoid congestion */
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
}

/* Public functions */
void send_wifi_scanner_indication(void) {
    if (!wifi_scanner_notify_enabled || gatt_svr_is_disconnected())
        return;

    wifi_scan_records_t *records = wifi_scan();
    if (!records) {
        return;
    }

    send_wifi_packets(records);
    free(records);
}

void send_rssi_once(void) {
    if (!wifi_rssi_notify_enabled || gatt_svr_is_disconnected())
        return;

    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        uint8_t rssi = ap.rssi;
        struct os_mbuf *om;
        om = ble_hs_mbuf_from_flat(&rssi, 1);
        if (!om) return;
        int rc = ble_gatts_notify_custom(ble_conn_handle,
                             wifi_rssi_chr_val_handle,
                             om);

        if (rc != 0) {
            os_mbuf_free_chain(om);
        }
        /* Yield a bit to avoid congestion */
        vTaskDelay(pdMS_TO_TICKS(20));
    }   
}

void gatt_svr_send_wifi_response(uint8_t code) {
    if (!wifi_control_notify_enabled || gatt_svr_is_disconnected())
        return;

    struct os_mbuf *om;
    om = ble_hs_mbuf_from_flat(&code, 1);
    if (!om) return;
    int rc = ble_gatts_notify_custom(ble_conn_handle,
                             wifi_control_chr_val_handle,
                             om);

    if (rc != 0)
        os_mbuf_free_chain(om);
        
    /* Yield a bit to avoid congestion */
    vTaskDelay(pdMS_TO_TICKS(20));
}

void send_throughput_response(uint8_t code) {
    if (!throughput_notify_enabled || gatt_svr_is_disconnected())
        return;

    struct os_mbuf *om;
    om = ble_hs_mbuf_from_flat(&code, 1);
    if (!om) return;
    int rc = ble_gatts_notify_custom(ble_conn_handle,
                             throughput_chr_val_handle,
                             om);

    if (rc != 0)
        os_mbuf_free_chain(om);
    

    /* Yield a bit to avoid congestion */
    vTaskDelay(pdMS_TO_TICKS(20));
}
/*
 *  Handle GATT attribute register events
 *      - Service register event
 *      - Characteristic register event
 *      - Descriptor register event
 */
void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg) {
    /* Local variables */
    char buf[BLE_UUID_STR_LEN];

    /* Handle GATT attributes register events */
    switch (ctxt->op) {

    /* Service register event */
    case BLE_GATT_REGISTER_OP_SVC:
        ESP_LOGD(TAG, "registered service %s with handle=%d",
                 ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
                 ctxt->svc.handle);
        break;

    /* Characteristic register event */
    case BLE_GATT_REGISTER_OP_CHR:
        ESP_LOGD(TAG,
                 "registering characteristic %s with "
                 "def_handle=%d val_handle=%d",
                 ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                 ctxt->chr.def_handle, ctxt->chr.val_handle);
        break;

    /* Descriptor register event */
    case BLE_GATT_REGISTER_OP_DSC:
        ESP_LOGD(TAG, "registering descriptor %s with handle=%d",
                 ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
                 ctxt->dsc.handle);
        break;

    /* Unknown event */
    default:
        assert(0);
        break;
    }
}

/*
 *  GATT server subscribe event callback
 *      1. Update wifi scanner subscription status
 */
void gatt_svr_subscribe_cb(struct ble_gap_event *event) {
    if (event->subscribe.cur_notify) {
        ble_conn_handle = event->subscribe.conn_handle;
    }
    if (event->subscribe.attr_handle == wifi_scan_chr_val_handle) {
        wifi_scanner_notify_enabled   = event->subscribe.cur_notify;
    } else if (event->subscribe.attr_handle == wifi_rssi_chr_val_handle) {
        wifi_rssi_notify_enabled      = event->subscribe.cur_notify;
    } else if (event->subscribe.attr_handle == wifi_control_chr_val_handle) {
        wifi_control_notify_enabled   = event->subscribe.cur_notify;
    } else if (event->subscribe.attr_handle == throughput_chr_val_handle) {
        throughput_notify_enabled = event->subscribe.cur_notify;
    }
}

/*
 *  GATT server connection predicate 
 */
bool gatt_svr_is_disconnected() {
    return ble_conn_handle == BLE_HS_CONN_HANDLE_NONE;
}

/*
 *  GATT server disconnect event callback
 *      1. Mark the connection handle invalid 
 *      2. Reset the notify flags
 */
void gatt_svr_disconnect_cb(void) {
    /* 1. Mark the connection handle invalid*/
    ble_conn_handle = BLE_HS_CONN_HANDLE_NONE;

    /* 2. Reset the notify flags */
    wifi_scanner_notify_enabled     = false;
    wifi_rssi_notify_enabled        = false;
    wifi_control_notify_enabled     = false;
    throughput_notify_enabled   = false;
}

/*
 *  GATT server initialization
 *      1. Initialize GATT service
 *      2. Update NimBLE host GATT services counter
 *      3. Add GATT services to server
 */
int gatt_svc_init(void) {
    /* Local variables */
    int rc;

    /* 1. GATT service initialization */
    ble_svc_gatt_init();

    /* 2. Update GATT services counter */
    rc = ble_gatts_count_cfg(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    /* 3. Add GATT services */
    rc = ble_gatts_add_svcs(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }
    return 0;
}
