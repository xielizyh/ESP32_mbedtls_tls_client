/**
 ***********************************************************************************************************************
 * Copyright (c) 2020, China Mobile Communications Group Co.,Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @file        app_net.c
 *
 * @brief       app_net functions.
 *
 * @revision
 * Date         Author          Notes
 * 2020-07-28   XieLi           First Version
 ***********************************************************************************************************************
 */
#include "nvs_flash.h"
#include "tcpip_adapter.h"
#include "esp_event.h"
#include "esp_system.h"
#include "protocol_examples_common.h"

/**
 ***********************************************************************************************************************
 * @brief           网络初始化
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
int app_net_init(void)
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    return 0;
}