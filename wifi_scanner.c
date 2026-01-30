#include "esp_err.h"
#include "esp_event.h"
#include "wifi_scanner.h"
#include <string.h>

#define DEFAULT_SCAN_LIST_SIZE 10 

extern QueueHandle_t wifi_evt_queue;

volatile wifi_state_t wifi_state = WIFI_IDLE;

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data);
static void wifi_ip_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data);


/* Initialize Wi-Fi as sta and set scan method */
esp_err_t wifi_scanner_init(void)
{
    esp_err_t err;

    err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    if (!netif) {
        return ESP_ERR_NO_MEM;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK && err != ESP_ERR_WIFI_INIT_STATE) {
        return err;
    }

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                           &wifi_event_handler, NULL);

    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                           &wifi_ip_event_handler, NULL);

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        return err;
    }

    err = esp_wifi_start();
    if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
        return err;
    }

    return ESP_OK;
}

wifi_scan_records_t* wifi_scan(void)
{
    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    static wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));

    ESP_ERROR_CHECK(esp_wifi_scan_start(NULL, true));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, ap_info));
    // ESP_LOGI(TAG, "Total APs scanned = %u, actual AP number ap_info holds = %u", ap_count, number);

    size_t size = sizeof(wifi_scan_records_t) +
                  number * sizeof(wifi_ap_record_t);

    wifi_scan_records_t *rec = malloc(size);
    if (!rec) {
        return NULL;
    }

    rec->count = number;
    memcpy(rec->records,
       ap_info,
       number * sizeof(wifi_ap_record_t));
    return rec;
}

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
    wifi_internal_evt_t evt;

    if (event_base == WIFI_EVENT) {
        switch (event_id) {

        case WIFI_EVENT_STA_CONNECTED:
            evt = WIFI_EVT_STA_CONNECTED;
            xQueueSend(wifi_evt_queue, &evt, 0);
            break;

        case WIFI_EVENT_STA_DISCONNECTED: {
            wifi_event_sta_disconnected_t *disc = event_data;

            if (disc->reason == WIFI_REASON_AUTH_FAIL ||
                disc->reason == WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT) {
                evt = WIFI_EVT_AUTH_FAILED;
            } else {
                evt = WIFI_EVT_STA_DISCONNECTED;
            }
            xQueueSend(wifi_evt_queue, &evt, 0);
            break;
        }
        }
    }

}
static void wifi_ip_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data) 
{
    wifi_internal_evt_t evt;
    if (event_base == IP_EVENT &&
        event_id == IP_EVENT_STA_GOT_IP) {
        evt = WIFI_EVT_GOT_IP;
        xQueueSend(wifi_evt_queue, &evt, 0);
    }
}
