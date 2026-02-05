#include "common.h"
#include "esp_timer.h"
#include "freertos/idf_additions.h"
#include "freertos/projdefs.h"
#include "gap.h"
#include "gatt_svc.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "portmacro.h"
#include "wifi_scanner.h"
#include <assert.h>
#include <sys/socket.h>

extern wifi_state_t volatile wifi_state;

/* Queues */
QueueHandle_t scan_cmd_queue;
QueueHandle_t wifi_rssi_cmd_queue;
QueueHandle_t control_cmd_queue;
QueueHandle_t wifi_evt_queue;
QueueHandle_t throughput_cmd_queue;
// QueueHandle_t udp_throughput_cmd_q

/* Timers */
static TimerHandle_t rssi_timer = NULL;
static uint32_t rssi_period_ms = 5000; 
                                       
/* Library function declarations */
void ble_store_config_init(void);

/* Private function declarations */
static void on_stack_reset(int reason);
static void on_stack_sync(void);
static void nimble_host_config_init(void);
static void nimble_host_task(void *param);

/* Private functions */
/*
 *  Stack event callback functions
 *      - on_stack_reset is called when host resets BLE stack due to errors
 *      - on_stack_sync is called when host has synced with controller
 */
static void on_stack_reset(int reason) {
    /* On reset, print reset reason to console */
    ESP_LOGI(TAG, "nimble stack reset, reset reason: %d", reason);
}

static void on_stack_sync(void) {
    /* On stack sync, do advertising initialization */
    adv_init();
}

static void nimble_host_config_init(void) {
    /* Set host callbacks */
    ble_hs_cfg.reset_cb = on_stack_reset;
    ble_hs_cfg.sync_cb = on_stack_sync;
    ble_hs_cfg.gatts_register_cb = gatt_svr_register_cb;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    // encryption
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
    ble_hs_cfg.sm_bonding = 1;
    // ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;   // LE Secure Connections

    /* Store host configuration */
    ble_store_config_init();
}

static void nimble_host_task(void *param) {
    /* Task entry log */
    ESP_LOGI(TAG, "nimble host task has been started!");

    /* This function won't return until nimble_port_stop() is executed */
    nimble_port_run();

    /* Clean up at exit */
    vTaskDelete(NULL);
}

static void rssi_timer_cb(TimerHandle_t t) {
    uint8_t cmd = CMD_SCAN_ONCE;
    xQueueSendFromISR(wifi_rssi_cmd_queue, &cmd, NULL);
}

void start_rssi_timer(void)
{
    if (!rssi_timer) {
        rssi_timer = xTimerCreate(
            "rssi_timer",
            pdMS_TO_TICKS(rssi_period_ms),
            pdTRUE,   // auto-reload
            NULL,
            rssi_timer_cb
        );
    }

    if (rssi_timer && xTimerIsTimerActive(rssi_timer) == pdFALSE) {
        xTimerStart(rssi_timer, 0);
    }
}

void stop_rssi_timer(void) {
    if(rssi_timer) {
        xTimerStop(rssi_timer, 0);
    }
}

void wifi_scan_task(void *arg)
{
    uint8_t cmd;
    bool continuous = false;

    uint64_t continuousStartTime = 0u;
    while (1) {
        if (xQueueReceive(scan_cmd_queue, &cmd,
                          continuous ? pdMS_TO_TICKS(6*1000) : portMAX_DELAY)) {

            switch (cmd) {

            case CMD_SCAN_ONCE:
                send_wifi_scanner_indication();
                break;

            case CMD_SCAN_START:
                continuous = true;
                continuousStartTime = esp_timer_get_time();
                break;

            case CMD_SCAN_STOP:
                continuous = false;
                break;
            }
        }

        if (continuous && (esp_timer_get_time() - continuousStartTime) < MAX_WIFI_CONTINUOUS_SCANNING_TIME_US) {
            send_wifi_scanner_indication();
        }
    }
    vTaskDelete(NULL);
}

void wifi_rssi_scan_task(void* arg) {
    uint8_t rssi_cmd;
    bool continuous = false;
    // TODO uint64_t continuousStartTime = 0u;
    while(1) {
        if (xQueueReceive(wifi_rssi_cmd_queue, &rssi_cmd, 
                    continuous ? pdMS_TO_TICKS(50) : portMAX_DELAY)) {
            switch (rssi_cmd) {
                case CMD_SCAN_ONCE:
                    if (wifi_state >= WIFI_CONNECTED) {
                        send_rssi_once();
                    }
                    break;
                case CMD_SCAN_START:
                    if (wifi_state == WIFI_CONNECTED) {
                        continuous = true;
                        start_rssi_timer();
                        wifi_state = WIFI_RSSI_CONTINUOUS;
                    }
                    break;
                case CMD_SCAN_STOP:
                    continuous = false;
                    stop_rssi_timer();
                    if (wifi_state == WIFI_RSSI_CONTINUOUS) {
                        wifi_state = WIFI_CONNECTED;
                    }
                    break;
            }
        }       
    }

    vTaskDelete(NULL);
}

void wifi_control_task(void* args) {
    wifi_control_cmd_t ctrl_cmd;
    wifi_internal_evt_t evt;
    while(1) {
        if (xQueueReceive(wifi_evt_queue, &evt, pdMS_TO_TICKS(50))) {
            switch (evt) {

            case WIFI_EVT_STA_CONNECTED:
                gatt_svr_send_wifi_response(RESP_WIFI_CONNECTED);
                break;

            case WIFI_EVT_GOT_IP:
                wifi_state = WIFI_CONNECTED;
                gatt_svr_send_wifi_response(RESP_IP_RECEIVED);
                break;

            case WIFI_EVT_AUTH_FAILED:
                wifi_state = WIFI_IDLE;
                break;

            case WIFI_EVT_STA_DISCONNECTED:
                wifi_state = WIFI_IDLE;
                gatt_svr_send_wifi_response(RESP_WIFI_DISCONNECTED);
                stop_rssi_timer();
                break;
            }
        }
        if (xQueueReceive(control_cmd_queue, &ctrl_cmd, pdMS_TO_TICKS(50))) {
            switch (ctrl_cmd.cmd) {
                case CMD_CONNECT:
                    // non-blocking connection
                    if (wifi_state != WIFI_IDLE)
                        break;

                    wifi_state = WIFI_CONNECTING;
                    esp_wifi_disconnect();
                    
                    wifi_config_t conf = {0};
                    memcpy(conf.sta.ssid, ctrl_cmd.creds.ssid, ctrl_cmd.creds.ssid_len);
                    conf.sta.ssid[ctrl_cmd.creds.ssid_len] = '\0';
                    memcpy(conf.sta.password, ctrl_cmd.creds.pass, ctrl_cmd.creds.pass_len);
                    conf.sta.password[ctrl_cmd.creds.pass_len] = '\0';

                    esp_wifi_set_config(ESP_IF_WIFI_STA, &conf);
                    esp_wifi_connect();
                    break;
                case CMD_DISCONNECT:
                    esp_wifi_disconnect();
                    wifi_state = WIFI_IDLE;
                    break;
            }
        }
    }
    vTaskDelete(NULL);
}

void run_tcp_client(sock_throughput_t* cfg) {
    ESP_LOGE(TAG, "tcp subroutine entered");
    // initializing a socket
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "tcp socket creation failed");
        return;
    }
    ESP_LOGI(TAG, "tcp socket created");

    int flag = 0;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    struct timeval tv = {
        .tv_sec = 5,
        .tv_usec = 0
    };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int sndbuf = 16 * 1024;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        ESP_LOGW(TAG, "SO_SNDBUF failed: errno=%d", errno);
    }
            
    // conecting
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = cfg->port;
    dest.sin_addr.s_addr = cfg->ipaddr; // already network order
                                        //
    ESP_LOGI(TAG, "Connecting to %s:%u",
         inet_ntoa(dest.sin_addr),
         ntohs(dest.sin_port));
    
    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        ESP_LOGE(TAG, "tcp connect failed");
        
        ESP_LOGE(TAG, "Port: %u", ntohs(dest.sin_port));
        ESP_LOGE(TAG, "IP: %s", inet_ntoa(dest.sin_addr));
        ESP_LOGE(TAG, "tcp connect failed, errno=%d (%s)", errno, strerror(errno));

        close(sock);
        return;
    }
    ESP_LOGI(TAG, "tcp connect succeeded");

    uint8_t buf[1460];
    memset(buf, 0xAA, sizeof(buf));

    int64_t start = esp_timer_get_time();
    int64_t end   = start + cfg->duration_sec * 1000000LL;

    while (esp_timer_get_time() < end) {
        if (wifi_state < WIFI_CONNECTED) {
            ESP_LOGW(TAG, "Wifi disconnected, aboring tcp throughput measurement");
            break;
        }

        uint8_t *p = buf;
        uint16_t toSend = sizeof(buf);

        // handle partial sending
        while (toSend > 0) {
            int ret = send(sock, p, toSend, 0);
            if (ret <= 0)  { 
                ESP_LOGE(TAG, "tcp send() failed");
                break;
            }
            p += ret;
            toSend -= ret;
        }
    }
    ESP_LOGE(TAG, "tcp subroutine finished");

    // finishing the tcp client
    shutdown(sock, SHUT_WR);
    vTaskDelay(pdMS_TO_TICKS(100));
    close(sock);
}

void run_udp_client(sock_throughput_t* cfg) {
    ESP_LOGE(TAG, "udp subroutine entered");
    // initializing socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "udp socket creation failed");
        return;
    }
    ESP_LOGE(TAG, "udp socket created");

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port   = cfg->port;
    dest.sin_addr.s_addr = cfg->ipaddr;

    uint8_t buf[1460];
    memset(buf, 0xAA, sizeof(buf));

    int64_t next_send = esp_timer_get_time();
    int64_t end = next_send + cfg->duration_sec * 1000000LL;
    // int64_t interval_us = 0;
    // sending
    while (esp_timer_get_time() < end) {
        if (wifi_state < WIFI_CONNECTED) {
            ESP_LOGW(TAG, "Wifi disconnected, aboring udp throughput measurement");
            break;
        }

        int ret = sendto(sock, buf, sizeof(buf), 0,
                     (struct sockaddr *)&dest, sizeof(dest));
        if (ret < 0) {
            if (errno == ENOMEM) {
                vTaskDelay(1); // let WiFi breathe
                continue;
            }
            ESP_LOGE(TAG, "sendto failed: errno=%d", errno);
            break;
        }

        // next_send += interval_us;
        // int64_t now = esp_timer_get_time();
        // if (next_send > now) {
        //     // esp_rom_delay_us(next_send - now);
        //     esp_rom_delay_us(100);
        // }
        // vTaskDelay(1);  // 1 tick
    }

    ESP_LOGE(TAG, "udp subroutine finishing");
    // finisshing udp socket
    close(sock);
}

void throughput_client_task(void* args) {
    sock_throughput_t cfg;
    while(1) {
        if(xQueueReceive(throughput_cmd_queue, &cfg, portMAX_DELAY)) {

            ESP_LOGI(TAG, "Queue read");
            if (wifi_state < WIFI_CONNECTED) {
                send_throughput_response(RESP_WIFI_DISCONNECTED);
                ESP_LOGI(TAG, "wifi not connected");
                continue;
            }
            
            ESP_LOGI(TAG, "Wifi connected");

            if (cfg.proto == IPPROTO_TCP) {
                run_tcp_client(&cfg);
                ESP_LOGI(TAG, "tcp recognized");
            }
            else if (cfg.proto == IPPROTO_UDP) {
                run_udp_client(&cfg);
                ESP_LOGI(TAG, "udp recognized");
            }
            ESP_LOGI(TAG, "processed the tcp/udp query");
            gatt_svr_send_wifi_response(RESP_THROUGHPUT_DONE);
        }
    }
    vTaskDelete(NULL); 
}

void app_main(void) {
    /* Local variables */
    int rc;
    esp_err_t ret;

    /*
     * NVS flash initialization
     * Dependency of BLE stack to store configurations
     */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "failed to initialize nvs flash, error code: %d ", ret);
        return;
    }

    /* NimBLE stack initialization */
    ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "failed to initialize nimble stack, error code: %d ",
                 ret);
        return;
    }
    ble_att_set_preferred_mtu(247);

    /* GAP service initialization */
    rc = gap_init();
    if (rc != 0) {
        ESP_LOGE(TAG, "failed to initialize GAP service, error code: %d", rc);
        return;
    }

    /* GATT server initialization */
    rc = gatt_svc_init();
    if (rc != 0) {
        ESP_LOGE(TAG, "failed to initialize GATT server, error code: %d", rc);
        return;
    }

    rc = wifi_scanner_init();
    if (rc != 0) {
        ESP_LOGE(TAG, "failed to initialize wifi scanner, error code: %d", rc);
        return;
    }
    /* NimBLE host configuration initialization */
    nimble_host_config_init();

    scan_cmd_queue           = xQueueCreate(4, sizeof(uint8_t));
    wifi_rssi_cmd_queue      = xQueueCreate(4, sizeof(uint8_t));
    control_cmd_queue        = xQueueCreate(4, sizeof(wifi_control_cmd_t));
    wifi_evt_queue           = xQueueCreate(8, sizeof(wifi_internal_evt_t));
    throughput_cmd_queue = xQueueCreate(4, sizeof(sock_throughput_t));
    assert(scan_cmd_queue);
    assert(wifi_rssi_cmd_queue);
    assert(control_cmd_queue);
    assert(wifi_evt_queue);
    assert(throughput_cmd_queue);

    /* Start NimBLE host task thread and return */
    xTaskCreate(nimble_host_task,   "NimBLE Host",  6*1024, NULL, 5, NULL);
    xTaskCreate(wifi_scan_task,     "Wifi Scan",    6*1024, NULL, 5, NULL);
    xTaskCreate(wifi_rssi_scan_task,"RSSI Scan",    6*1024, NULL, 5, NULL);
    xTaskCreate(wifi_control_task,  "Control",      6*1024, NULL, 5, NULL);
    xTaskCreate(throughput_client_task,    "Throuput", 6*1024, NULL, 5, NULL);
    return;
}

// esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);
