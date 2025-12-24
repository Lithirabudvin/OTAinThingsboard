/**
 * @file main.c
 */

#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "cJSON.h"

#include "main.h"
#include "wifi.h"

#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "mqtt_client.h"

#include "nvs.h"
#include "nvs_flash.h"

extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

/*! Saves bit values used in application */
static EventGroupHandle_t event_group;

/*! Saves OTA config received from ThingsBoard*/
static struct shared_keys
{
    char fw_url[256];
    char targetFwVer[128];
} shared_attributes;

/*! Buffer to save a received MQTT message */
static char mqtt_msg[512];

static esp_mqtt_client_handle_t mqtt_client;

static void parse_ota_config(const cJSON *object)
{
    if (object != NULL)
    {
        cJSON *fw_ver_response = cJSON_GetObjectItem(object, "fw_version");
        cJSON *fw_title_response = cJSON_GetObjectItem(object, "fw_title");
        
        if (cJSON_IsString(fw_ver_response) && (fw_ver_response->valuestring != NULL) &&
            cJSON_IsString(fw_title_response) && (fw_title_response->valuestring != NULL))
        {
            strncpy(shared_attributes.targetFwVer, fw_ver_response->valuestring, 
                    sizeof(shared_attributes.targetFwVer) - 1);
            
            // Build the URL with query parameters using CONFIG_MQTT_ACCESS_TOKEN
            snprintf(shared_attributes.fw_url, sizeof(shared_attributes.fw_url), 
                    "http://demo.thingsnode.cc:8080/api/v1/%s/firmware?title=%s&version=%s", 
                    CONFIG_MQTT_ACCESS_TOKEN,         // Use from config instead of hardcoded
                    fw_title_response->valuestring,  
                    fw_ver_response->valuestring);

            ESP_LOGI(TAG, "Firmware found in attributes! Target: %s", shared_attributes.targetFwVer);
            ESP_LOGI(TAG, "Firmware URL: %s", shared_attributes.fw_url);
        }
        else 
        {
            ESP_LOGW(TAG, "fw_version or fw_title not found in this JSON object");
        }
    }
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        xEventGroupClearBits(event_group, MQTT_DISCONNECTED_EVENT);
        xEventGroupSetBits(event_group, MQTT_CONNECTED_EVENT);
        ESP_LOGD(TAG, "MQTT_EVENT_CONNECTED");
        break;
    case MQTT_EVENT_DISCONNECTED:
        xEventGroupClearBits(event_group, MQTT_CONNECTED_EVENT);
        xEventGroupSetBits(event_group, MQTT_DISCONNECTED_EVENT);
        ESP_LOGD(TAG, "MQTT_EVENT_DISCONNECTED");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGD(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGD(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGD(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGD(TAG, "MQTT_EVENT_DATA, msg_id=%d", event->msg_id);
        if (event->data_len >= (sizeof(mqtt_msg) - 1))
        {
            ESP_LOGE(TAG, "Received MQTT message size [%d] more than expected [%d]", event->data_len, (sizeof(mqtt_msg) - 1));
            return;
        }

        // Compare topic using strncmp with topic_len
        if (strncmp(TB_ATTRIBUTES_RESPONSE_TOPIC, event->topic, event->topic_len) == 0)
        {
            memcpy(mqtt_msg, event->data, event->data_len);
            mqtt_msg[event->data_len] = 0;
            cJSON *attributes = cJSON_Parse(mqtt_msg);
            if (attributes != NULL)
            {
                cJSON *shared = cJSON_GetObjectItem(attributes, "shared");
                parse_ota_config(shared);
            }
            // Inside MQTT_EVENT_DATA, after cJSON_Parse
            char *debug_ptr = cJSON_Print(attributes);
            ESP_LOGI("DEBUG_JSON", "Full Response: %s", debug_ptr);
            free(debug_ptr);

            char *attributes_string = cJSON_Print(attributes);
            cJSON_Delete(attributes);
            ESP_LOGD(TAG, "Shared attributes response: %s", attributes_string);
            // Free is intentional, it's client responsibility to free the result of cJSON_Print
            free(attributes_string);
            xEventGroupSetBits(event_group, OTA_CONFIG_FETCHED_EVENT);
        }
        else if (strncmp(TB_ATTRIBUTES_TOPIC, event->topic, event->topic_len) == 0)
        {
            memcpy(mqtt_msg, event->data, MIN(event->data_len, sizeof(mqtt_msg)));
            mqtt_msg[event->data_len] = 0;
            cJSON *attributes = cJSON_Parse(mqtt_msg);
            parse_ota_config(attributes);
            char *attributes_string = cJSON_Print(attributes);
            cJSON_Delete(attributes);
            ESP_LOGD(TAG, "Shared attributes were updated on ThingsBoard: %s", attributes_string);
            // Free is intentional, it's client responsibility to free the result of cJSON_Print
            free(attributes_string);
            xEventGroupSetBits(event_group, OTA_CONFIG_UPDATED_EVENT);
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGD(TAG, "MQTT_EVENT_ERROR");
        break;
    case MQTT_EVENT_BEFORE_CONNECT:
        ESP_LOGD(TAG, "MQTT_EVENT_BEFORE_CONNECT");
        break;
    default:
        break;
    }
}

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    assert(evt != NULL);

    switch (evt->event_id)
    {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            // Write out data
            ESP_LOGD(TAG, "%.*s", evt->data_len, (char *)evt->data);
        }
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
        break;
    }
    return ESP_OK;
}

/**
 * @brief Main application task, it sends counter value to ThingsBoard telemetry MQTT topic.
 *
 * @param pvParameters Pointer to the task arguments
 */
static void main_application_task(void *pvParameters)
{
    uint8_t counter = 0;

    while (1)
    {
        xEventGroupWaitBits(event_group, OTA_TASK_IN_NORMAL_STATE_EVENT, false, true, portMAX_DELAY);

        counter = counter < 1 ? counter + 1 : 0;

        cJSON *root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "counter", counter);
        char *post_data = cJSON_PrintUnformatted(root);
        esp_mqtt_client_publish(mqtt_client, TB_TELEMETRY_TOPIC, post_data, 0, 1, 0);
        cJSON_Delete(root);
        // Free is intentional, it's client responsibility to free the result of cJSON_Print
        free(post_data);

        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

/**
 * @brief Check is the current running partition label is factory
 *
 * @return true The factory partition is running
 * @return false The ota partition is running
 */
static bool is_running_from_factory_partition(const char *running_partition_label)
{
    assert(running_partition_label != NULL);
    return strcmp(FACTORY_PARTITION_LABEL, running_partition_label) == 0 ? true : false;
}

/**
 * @brief Get MQTT client configuration parameters from NVS storage if OTA partition is running.
 *        If factory partition is running, then gets MQTT client configuration parameters from Config.
 *
 * @param running_partition_label Pointer to null-terminated string containing the current running partition label
 * @param mqtt_config Pointer to the memory to save MQTT client configuration
 *
 * @return ESP_OK - the mqtt_config was filled
 * @return ESP_FAIL - failed to get parameters from NVS or Config
 */
static esp_err_t get_mqtt_config(const char *running_partition_label, esp_mqtt_client_config_t *mqtt_config)
{
    assert(running_partition_label != NULL && mqtt_config != NULL);

    // We still open NVS to ensure we can save the new config for other parts of the system
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        return ESP_FAIL;
    }

    // FORCE "First boot" logic every time to override NVS with Menuconfig values
    ESP_LOGI(TAG, "FORCED: MQTT configuration from Config (Menuconfig) is used");
    
    // Allocate memory for URI
// Change the allocation for URI (around line 265 in main.c)
    char *uri = malloc(MAX_LENGTH_TB_URL + 1); // Add +1 for safety
    if (uri == NULL) {
        nvs_close(nvs_handle);
        return ESP_FAIL;
    }

    // Update the snprintf to use the safe size
    snprintf(uri, MAX_LENGTH_TB_URL + 1, "%s", CONFIG_MQTT_BROKER_URL);
    mqtt_config->broker.address.uri = uri;
    // Allocate and set access token
    char *token = malloc(MAX_LENGTH_TB_ACCESS_TOKEN + 1); 
    if (token == NULL) {
        free((void*)mqtt_config->broker.address.uri);
        nvs_close(nvs_handle);
        return ESP_FAIL;
    }
    snprintf(token, MAX_LENGTH_TB_ACCESS_TOKEN + 1, "%s", CONFIG_MQTT_ACCESS_TOKEN);
    mqtt_config->credentials.username = token;

    // Overwrite whatever was in NVS with the new Menuconfig values
    nvs_set_str(nvs_handle, NVS_KEY_MQTT_URL, mqtt_config->broker.address.uri);
    nvs_set_u32(nvs_handle, NVS_KEY_MQTT_PORT, CONFIG_MQTT_BROKER_PORT);
    nvs_set_str(nvs_handle, NVS_KEY_MQTT_ACCESS_TOKEN, mqtt_config->credentials.username);
    nvs_commit(nvs_handle);

    nvs_close(nvs_handle);

    ESP_LOGI(TAG, "MQTT broker URL: %s", mqtt_config->broker.address.uri);
    ESP_LOGI(TAG, "MQTT access token: %s", mqtt_config->credentials.username);

    return ESP_OK;
}

/**
 * @brief Starts the MQTT application
 *
 * @param running_partition_label Pointer to null-terminated string containing the current running partition label
 */
static void mqtt_app_start(const char *running_partition_label)
{
    assert(running_partition_label != NULL);

    esp_mqtt_client_config_t mqtt_cfg = {
        // .broker.verification.certificate = (const char *)server_cert_pem_start,  // Commented out for non-SSL MQTT
    };

    if (get_mqtt_config(running_partition_label, &mqtt_cfg) != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to get MQTT configuration");
        APP_ABORT_ON_ERROR(ESP_FAIL);
    }

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (mqtt_client == NULL)
    {
        ESP_LOGE(TAG, "Failed to initialize MQTT client");
        APP_ABORT_ON_ERROR(ESP_FAIL);
    }

    APP_ABORT_ON_ERROR(esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL));
    APP_ABORT_ON_ERROR(esp_mqtt_client_start(mqtt_client));
}

/**
 * @brief Validate the OTA download but don't apply it yet
 *
 * @param url URL of the firmware image
 * @return ESP_OK on success
 */
 
static void publish_fw_state(const char *state, const char *fw_title, const char *fw_version)
{
    cJSON *telemetry = cJSON_CreateObject();
    cJSON_AddStringToObject(telemetry, "fw_state", state);
    cJSON_AddStringToObject(telemetry, "current_fw_title", fw_title);
    cJSON_AddStringToObject(telemetry, "current_fw_version", fw_version);
    
    char *telemetry_json = cJSON_PrintUnformatted(telemetry);
    cJSON_Delete(telemetry);
    
    int msg_id = esp_mqtt_client_publish(mqtt_client, TB_TELEMETRY_TOPIC, telemetry_json, 0, 1, 0);
    
    if (msg_id >= 0) {
        ESP_LOGI(TAG, "Published fw_state=%s (msg_id=%d)", state, msg_id);
    } else {
        ESP_LOGE(TAG, "Failed to publish fw_state=%s", state);
    }
    
    free(telemetry_json);
    vTaskDelay(500 / portTICK_PERIOD_MS);
}


static esp_err_t validate_image_and_update(const char *url)
{
    assert(url != NULL);
    publish_fw_state("DOWNLOADING", "ESP32C5", FIRMWARE_VERSION);
    esp_http_client_config_t http_config = {
        .url = url,
        .event_handler = _http_event_handler,
        .keep_alive_enable = true,
        .timeout_ms = 10000,
        .buffer_size = 1024,
        .buffer_size_tx = 1024,
    };

    // Check if URL is HTTP or HTTPS
    if (strncmp(url, "http://", 7) == 0) {
        ESP_LOGW(TAG, "Using insecure HTTP connection for OTA");
        // For HTTP URLs, we must set these to NULL/false
        http_config.cert_pem = NULL;
        http_config.skip_cert_common_name_check = false;
        http_config.use_global_ca_store = false;
        http_config.crt_bundle_attach = NULL;  // Critical for HTTP!
    } else {
        ESP_LOGI(TAG, "Using HTTPS connection for OTA");
        http_config.cert_pem = NULL;
        http_config.skip_cert_common_name_check = true;
    }

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
        .bulk_flash_erase = false,
        .partial_http_download = false,
    };

    esp_https_ota_handle_t https_ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ESP HTTPS OTA Begin failed (0x%x)", err);
        publish_fw_state("FAILED", "ESP32C5", FIRMWARE_VERSION);  
        return err;
    }

    esp_app_desc_t app_desc;
    err = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_https_ota_get_img_desc failed (0x%x)", err);
        publish_fw_state("FAILED", "ESP32C5", FIRMWARE_VERSION);
        goto ota_end;
    }

    ESP_LOGI(TAG, "New firmware version detected: %s", app_desc.version);

    while (1)
    {
        err = esp_https_ota_perform(https_ota_handle);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS)
        {
            break;
        }
        ESP_LOGI(TAG, "Image bytes read: %d", esp_https_ota_get_image_len_read(https_ota_handle));
    }

    if (esp_https_ota_is_complete_data_received(https_ota_handle) != true)
    {
        ESP_LOGE(TAG, "Complete data was not received.");
        publish_fw_state("FAILED", "ESP32C5", FIRMWARE_VERSION); 
        err = ESP_FAIL;
    }
    else
    {  
        publish_fw_state("DOWNLOADED", "ESP32C5", FIRMWARE_VERSION);
        
        // Report VERIFIED
        publish_fw_state("VERIFIED", "ESP32C5", FIRMWARE_VERSION);
        
        // Report UPDATING (about to flash)
        publish_fw_state("UPDATING", "ESP32C5", FIRMWARE_VERSION);

        err = esp_https_ota_finish(https_ota_handle);
        if (err == ESP_OK)
        {
            ESP_LOGI(TAG, "OTA update successful. Rebooting...");
            vTaskDelay(2000 / portTICK_PERIOD_MS);
            esp_restart();
        }
        else
        {
            ESP_LOGE(TAG, "ESP_HTTPS_OTA upgrade failed 0x%x", err);
            publish_fw_state("FAILED", "ESP32C5", FIRMWARE_VERSION);
        }
    }

ota_end:
    esp_https_ota_abort(https_ota_handle);
    return err;
}

/**
 * @brief Check if OTA should be performed and start it if needed
 *
 * @param current_fw_ver Current firmware version
 * @param shared_attr Shared attributes containing target firmware info
 */
static void start_ota(const char *current_fw_ver, struct shared_keys shared_attr)
{
    if (shared_attr.fw_url[0] == '\0' || shared_attr.targetFwVer[0] == '\0')
    {
        ESP_LOGI(TAG, "OTA config is empty");
        return;
    }

    // ADD THESE DEBUG LINES:
    ESP_LOGI(TAG, "=== OTA Version Check ===");
    ESP_LOGI(TAG, "Current FW: '%s'", current_fw_ver);
    ESP_LOGI(TAG, "Target FW:  '%s'", shared_attr.targetFwVer);
    ESP_LOGI(TAG, "Comparison: %d", strcmp(shared_attr.targetFwVer, current_fw_ver));
    ESP_LOGI(TAG, "========================");

    if (strcmp(shared_attr.targetFwVer, current_fw_ver) == 0)
    {
        ESP_LOGI(TAG, "Current firmware version is the same as target version. No OTA needed.");
        publish_fw_state("UPDATED", "ESP32C5", current_fw_ver);
        return;
    }

    ESP_LOGI(TAG, "Starting OTA from: %s", shared_attr.fw_url);
    
    esp_err_t ota_result = validate_image_and_update(shared_attr.fw_url);
    
    // Add this block:
    if (ota_result != ESP_OK) {
        ESP_LOGE(TAG, "OTA failed with error: 0x%x", ota_result);
        publish_fw_state("FAILED", "ESP32C5", current_fw_ver);
    }
}

/**
 * @brief Check connection state and return appropriate state
 *
 * @param actual_event Current event flags
 * @param state_name Name of current state for logging
 * @return enum state
 */
static enum state connection_state(BaseType_t actual_event, const char *state_name)
{
    if (actual_event & WIFI_DISCONNECTED_EVENT)
    {
        ESP_LOGW(TAG, "%s state, Wi-Fi not connected, wait for the connect", state_name);
        return STATE_WAIT_WIFI;
    }

    if (actual_event & MQTT_DISCONNECTED_EVENT)
    {
        ESP_LOGW(TAG, "%s state, MQTT not connected, wait for the connect", state_name);
        return STATE_WAIT_MQTT;
    }

    return STATE_CONNECTION_IS_OK;
}

/**
 * @brief OTA task, it handles the shared attributes updates and starts OTA if the config received from ThingsBoard is valid.
 *
 * @param pvParameters Pointer to the task arguments
 */
static void ota_task(void *pvParameters)
{
    enum state current_connection_state = STATE_CONNECTION_IS_OK;
    enum state state = STATE_INITIAL;
    BaseType_t actual_event = 0x00;
    char running_partition_label[17]; // Max partition label length is 16 + null terminator

    while (1)
    {
        if (state != STATE_INITIAL && state != STATE_APP_LOOP)
        {
            if (state != STATE_APP_LOOP)
            {
                xEventGroupClearBits(event_group, OTA_TASK_IN_NORMAL_STATE_EVENT);
            }

            actual_event = xEventGroupWaitBits(event_group,
                                               WIFI_CONNECTED_EVENT | WIFI_DISCONNECTED_EVENT | MQTT_CONNECTED_EVENT | MQTT_DISCONNECTED_EVENT | OTA_CONFIG_FETCHED_EVENT,
                                               false, false, portMAX_DELAY);
        }

        switch (state)
        {
        case STATE_INITIAL:
        {
            // Initialize NVS.
            esp_err_t err = nvs_flash_init();
            if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
            {
                // OTA app partition table has a smaller NVS partition size than the non-OTA
                // partition table. This size mismatch may cause NVS initialization to fail.
                // If this happens, we erase NVS partition and initialize NVS again.
                APP_ABORT_ON_ERROR(nvs_flash_erase());
                err = nvs_flash_init();
            }
            APP_ABORT_ON_ERROR(err);

            const esp_partition_t *running_partition = esp_ota_get_running_partition();
            strncpy(running_partition_label, running_partition->label, sizeof(running_partition_label) - 1);
            running_partition_label[sizeof(running_partition_label) - 1] = '\0';
            ESP_LOGI(TAG, "Running partition: %s", running_partition_label);

            initialise_wifi(running_partition_label);
            state = STATE_WAIT_WIFI;
            break;
        }

        case STATE_WAIT_WIFI:
        {
            if (actual_event & WIFI_DISCONNECTED_EVENT)
            {
                ESP_LOGW(TAG, "WAIT_WIFI state, Wi-Fi not connected, wait for the connect");
                state = STATE_WAIT_WIFI;
                break;
            }

            if (actual_event & WIFI_CONNECTED_EVENT)
            {
                mqtt_app_start(running_partition_label);
                state = STATE_WAIT_MQTT;
                break;
            }

            ESP_LOGE(TAG, "WAIT_WIFI state, unexpected event received: %ld", (long)actual_event);
            state = STATE_INITIAL;
            break;
            }
        case STATE_WAIT_MQTT:
        {
            current_connection_state = connection_state(actual_event, "WAIT_MQTT");
            if (current_connection_state != STATE_CONNECTION_IS_OK)
            {
                state = current_connection_state;
                break;
            }

            if (actual_event & (WIFI_CONNECTED_EVENT | MQTT_CONNECTED_EVENT))
            {
                ESP_LOGI(TAG, "Connected to MQTT broker %s, on port %d", CONFIG_MQTT_BROKER_URL, CONFIG_MQTT_BROKER_PORT);
                
                // Report initial state as UPDATED
                publish_fw_state("UPDATED", "ESP32C5", FIRMWARE_VERSION);
                
                vTaskDelay(2000 / portTICK_PERIOD_MS);

                // Now subscribe and request shared attributes
                int sub_result = esp_mqtt_client_subscribe(mqtt_client, TB_ATTRIBUTES_SUBSCRIBE_TO_RESPONSE_TOPIC, 1);
                ESP_LOGI(TAG, "Subscription result: %d", sub_result);
                
                vTaskDelay(500 / portTICK_PERIOD_MS);
                
                int req_msg_id = esp_mqtt_client_publish(mqtt_client, TB_ATTRIBUTES_REQUEST_TOPIC, TB_SHARED_ATTR_KEYS_REQUEST, 0, 1, 0);
                ESP_LOGI(TAG, "Requested shared attributes (msg_id=%d)", req_msg_id);

                state = STATE_WAIT_OTA_CONFIG_FETCHED;
                break;
            }
                    
            ESP_LOGE(TAG, "WAIT_MQTT state, unexpected event received: %ld", (long)actual_event);
            state = STATE_INITIAL;
            break;
        }        
        case STATE_WAIT_OTA_CONFIG_FETCHED:
        {
            current_connection_state = connection_state(actual_event, "WAIT_OTA_CONFIG_FETCHED");
            if (current_connection_state != STATE_CONNECTION_IS_OK)
            {
                state = current_connection_state;
                break;
            }

            if (actual_event & (WIFI_CONNECTED_EVENT | MQTT_CONNECTED_EVENT))
            {
                if (actual_event & OTA_CONFIG_FETCHED_EVENT)
                {
                    ESP_LOGI(TAG, "Shared attributes were fetched from ThingsBoard");
                    xEventGroupClearBits(event_group, OTA_CONFIG_FETCHED_EVENT);
                    state = STATE_OTA_CONFIG_FETCHED;
                    break;
                }

                state = STATE_WAIT_OTA_CONFIG_FETCHED;
                break;
            }

            ESP_LOGE(TAG, "WAIT_OTA_CONFIG_FETCHED state, unexpected event received: %ld", (long)actual_event);
            state = STATE_INITIAL;
            break;
        }
        case STATE_OTA_CONFIG_FETCHED:
        {
            current_connection_state = connection_state(actual_event, "OTA_CONFIG_FETCHED");
            if (current_connection_state != STATE_CONNECTION_IS_OK)
            {
                state = current_connection_state;
                break;
            }

            if (actual_event & (WIFI_CONNECTED_EVENT | MQTT_CONNECTED_EVENT))
            {
                // start_ota handles all state reporting internally
                start_ota(FIRMWARE_VERSION, shared_attributes);
                
                vTaskDelay(1000 / portTICK_PERIOD_MS);
                
                // Subscribe to future updates
                int sub_result = esp_mqtt_client_subscribe(mqtt_client, TB_ATTRIBUTES_TOPIC, 1);
                ESP_LOGI(TAG, "Subscribed to shared attributes updates (result=%d)", sub_result);
                                
                state = STATE_APP_LOOP;
                break;
            }
            
            ESP_LOGE(TAG, "OTA_CONFIG_FETCHED state, unexpected event received: %ld", (long)actual_event);
            state = STATE_INITIAL;
            break;
        }
        case STATE_APP_LOOP:
        {
            current_connection_state = connection_state(actual_event, "APP_LOOP");
            if (current_connection_state != STATE_CONNECTION_IS_OK)
            {
                state = current_connection_state;
                break;
            }

            if (actual_event & (WIFI_CONNECTED_EVENT | MQTT_CONNECTED_EVENT))
            {
                BaseType_t ota_events = xEventGroupWaitBits(event_group, OTA_CONFIG_UPDATED_EVENT, false, true, 0);
                if ((ota_events & OTA_CONFIG_UPDATED_EVENT))
                {
                    ESP_LOGI(TAG, "OTA config updated, attempting OTA");
                    
                    // start_ota handles all state reporting internally
                    start_ota(FIRMWARE_VERSION, shared_attributes);
                }
                
                xEventGroupClearBits(event_group, OTA_CONFIG_UPDATED_EVENT);
                xEventGroupSetBits(event_group, OTA_TASK_IN_NORMAL_STATE_EVENT);
                state = STATE_APP_LOOP;
                break;
            }

            ESP_LOGE(TAG, "APP_LOOP state, unexpected event received: %ld", (long)actual_event);
            state = STATE_INITIAL;
            break;
        }
        default:
        {
            ESP_LOGE(TAG, "Unexpected state");
            state = STATE_INITIAL;
            break;
        }
        }

        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

void app_main()
{
    event_group = xEventGroupCreate();
    xTaskCreate(&ota_task, "ota_task", 8192, NULL, 5, NULL);
    xTaskCreate(&main_application_task, "main_application_task", 8192, NULL, 5, NULL);
}

void notify_wifi_connected()
{
    xEventGroupClearBits(event_group, WIFI_DISCONNECTED_EVENT);
    xEventGroupSetBits(event_group, WIFI_CONNECTED_EVENT);
}

void notify_wifi_disconnected()
{
    xEventGroupClearBits(event_group, WIFI_CONNECTED_EVENT);
    xEventGroupSetBits(event_group, WIFI_DISCONNECTED_EVENT);
}