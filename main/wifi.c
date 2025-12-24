/**
 * @file wifi.c
 */

#include <string.h>
#include <sys/param.h>

#include "wifi.h"
#include "main.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_netif.h"

/*! Buffer to save ESP32 MAC address */
uint8_t esp32_mac[6];

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        /* Auto-reconnect */
        esp_wifi_connect();
        notify_wifi_disconnected();
        ESP_LOGI(TAG, "Wi-Fi disconnected, attempting to reconnect...");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        notify_wifi_connected();
        ESP_LOGI(TAG, "Connected to Wi-Fi, IP address: " IPSTR, IP2STR(&event->ip_info.ip));
    }
}

void initialise_wifi(const char *running_partition_label)
{
    assert(running_partition_label != NULL);

    // Initialize network interface
    APP_ABORT_ON_ERROR(esp_netif_init());
    
    // Create default event loop
    APP_ABORT_ON_ERROR(esp_event_loop_create_default());
    
    // Create default WiFi station
    esp_netif_create_default_wifi_sta();

    // Initialize WiFi with default config
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    APP_ABORT_ON_ERROR(esp_wifi_init(&cfg));

    // Register event handlers
    APP_ABORT_ON_ERROR(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    APP_ABORT_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    APP_ABORT_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_FLASH));

    wifi_config_t wifi_config = {};
    APP_ABORT_ON_ERROR(esp_wifi_get_config(WIFI_IF_STA, &wifi_config));

    if (wifi_config.sta.ssid[0] == '\0' || wifi_config.sta.password[0] == '\0')
    {
        ESP_LOGW(TAG, "Flash memory doesn't contain any Wi-Fi credentials, using credentials from Config");
        
        // Use memcpy to safely copy credentials
        memset(&wifi_config, 0, sizeof(wifi_config));
        memcpy(wifi_config.sta.ssid, WIFI_SSID, strlen(WIFI_SSID));
        memcpy(wifi_config.sta.password, WIFI_PASS, strlen(WIFI_PASS));
        wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
        wifi_config.sta.pmf_cfg.capable = true;
        wifi_config.sta.pmf_cfg.required = false;
    }
    else
    {
        ESP_LOGI(TAG, "Wi-Fi credentials from flash memory: %s", wifi_config.sta.ssid);
    }

    APP_ABORT_ON_ERROR(esp_wifi_get_mac(WIFI_IF_STA, esp32_mac));
    ESP_LOGI(TAG, "MAC address: %02X:%02X:%02X:%02X:%02X:%02X", 
             esp32_mac[0], esp32_mac[1], esp32_mac[2], 
             esp32_mac[3], esp32_mac[4], esp32_mac[5]);
    
    APP_ABORT_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA));
    APP_ABORT_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    APP_ABORT_ON_ERROR(esp_wifi_start());
}