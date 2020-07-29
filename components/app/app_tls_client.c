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
 * @file        app_tls_client.c
 *
 * @brief       app_tls_client functions.
 *
 * @revision
 * Date         Author          Notes
 * 2020-07-28   XieLi           First Version
 ***********************************************************************************************************************
 */
#include <string.h>

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

/* 根证书 */
#include "ca_cert.h"

//#define CONFIG_MBEDTLS_DEBUG

#ifdef CONFIG_MBEDTLS_DEBUG
#include "mbedtls/debug.h"
#define CONFIG_MBEDTLS_DEBUG_LEVEL 4
#endif

/* 服务端信息 */
#if 1
#define SERVER_ADDR         "114.55.142.4"
#define SERVER_PORT         "442"
#define HOST_NAME           "xieli.org"     /* 注意需要和证书名称中CN(Common Name)一致 */
#define GET_REQUEST         "GET /index.html HTTP/1.0\r\n\r\n"
#elif 0
#define SERVER_ADDR         "114.55.142.4"
#define SERVER_PORT         "4433"
#define HOST_NAME           "xieli.org"     /* 注意需要和证书名称中CN(Common Name)一致 */
#define GET_REQUEST         "GET /index.html HTTP/1.0\r\n\r\n"
#elif 0
#define SERVER_ADDR         "iotwuxi.org"
#define SERVER_PORT         "442"
#define HOST_NAME           "iotwuxi.org"
#define GET_REQUEST         "GET /index.html HTTP/1.0\r\n\r\n"
#else
#define SERVER_ADDR         "www.howsmyssl.com"
#define SERVER_PORT         "443"
#define HOST_NAME           "www.howsmyssl.com"     /* 注意需要和证书名称中CN(Common Name)一致 */
#define GET_REQUEST         "GET " "https://www.howsmyssl.com/a/check" " HTTP/1.0\r\n""Host: ""www.howsmyssl.com""\r\n""User-Agent: esp-idf/1.0 esp32\r\n""\r\n"
#endif

/* 根证书 
 * 直接使用.pem格式嵌入或者转换为.h文件(ca_cert.h)   
 */
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

/* 任务信息 */
#define TLS_CLIENT_TASK_STK_SIZE      10240
#define TLS_CLIENT_TASK_PRIO          5

/* 任务句柄 */
static TaskHandle_t tls_client_task_handler;

static const char *TAG = "tls_client";

/* assert_abort */
#define assert_abort(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

#ifdef CONFIG_MBEDTLS_DEBUG
/**
 ***********************************************************************************************************************
 * @brief           调试
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */

static void _tls_client_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    const char *p, *basename;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++)
    {
        if (*p == '/' || *p == '\\')
        {
            basename = p + 1;
        }
    }

    printf("%s:%04d: |%d| %s", basename, line, level, str);
}
#endif

/**
 ***********************************************************************************************************************
 * @brief           熵源接口
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
static int entropy_source(void *data, uint8_t *output, size_t len, size_t *olen)
{
    uint32_t seed = 0;
    //ARG_UNUSED(data);
#if 1
    seed = esp_random();
#else
    seed = rand();
#endif
    if (len > sizeof(seed))
    {
        len = sizeof(seed);
    }
    memcpy(output, &seed, len);

    *olen = len;

    return 0;
}

/**
 ***********************************************************************************************************************
 * @brief           tls客户端线程
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
static void tls_client_task(void *arg)
{
    int ret, len = 0;
    uint8_t request_count = 0;                    /* 请求次数 */
    unsigned char buf[256] = {0};
    const char *pers = "tls_client";        /* 个性化字符串 */
    mbedtls_entropy_context entropy;        /* 熵源 */
    mbedtls_ctr_drbg_context ctr_drbg;      /* 随机数 */
    //mbedtls_platform_set_printf(printf);
    //mbedtls_platform_set_snprintf(snprintf);

    mbedtls_x509_crt cert;                  /* x509证书结构体 */
    mbedtls_ssl_context ssl;                /* 网络结构体 */
    mbedtls_ssl_config conf;                /* ssl结构体 */
    mbedtls_net_context ctx;                /* ssl配置结构体 */

    mbedtls_net_init(&ctx);                 /* 初始化网络结构体 */
    mbedtls_ssl_init(&ssl);                 /* 初始化ssl结构体 */
    mbedtls_x509_crt_init(&cert);           /* 初始化x509证书结构体 */
    mbedtls_ctr_drbg_init(&ctr_drbg);       /* 随机数结构体初始化 */   
    mbedtls_ssl_config_init(&conf);         /* 初始化ssl配置结构体 */
    
    ESP_LOGI(TAG, "Seeding the random number generator...");
    /* 熵源结构体初始化 */
    mbedtls_entropy_init(&entropy);         
    /* 添加熵源接口，设置熵源属性 */
    mbedtls_entropy_add_source(&entropy, entropy_source, NULL, MBEDTLS_ENTROPY_MAX_GATHER, MBEDTLS_ENTROPY_SOURCE_STRONG);
    /* 根据个性化字符串更新种子 */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t *)pers, strlen(pers));   
    assert_abort(ret == 0, ret);

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");
    /* 加载ssl默认配置选项 */
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    assert_abort(ret == 0, ret);

    /* 设置随机数生成器回调接口 */
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    /* DER格式X.509证书解析 */
    ESP_LOGI(TAG, "Loading the CA root certificate...");
    ret = mbedtls_x509_crt_parse_der(&cert, ca_cert_der, ca_cert_der_len);
    //ret = mbedtls_x509_crt_parse(&cert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);
    assert_abort(ret == 0, ret);

    /* 配置证书链 */
    mbedtls_ssl_conf_ca_chain(&conf, &cert, NULL);
    /* 配置认证模式 */
    mbedtls_ssl_conf_authmode(&conf, /*MBEDTLS_SSL_VERIFY_REQUIRED*/MBEDTLS_SSL_VERIFY_OPTIONAL);

#if defined(CONFIG_MBEDTLS_DEBUG)
    mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG_LEVEL);
    mbedtls_ssl_conf_dbg(&conf, _tls_client_debug, NULL);
#endif

    /* 通过配置选项完成ssl的设置 */
    ret = mbedtls_ssl_setup(&ssl, &conf);
    assert_abort(ret == 0, ret);

    /* 配置ssl hostname */
    ret = mbedtls_ssl_set_hostname(&ssl, HOST_NAME);
    assert_abort(ret == 0, ret);

    while (1)
    {
        ESP_LOGI(TAG, "Connecting to %s:%s...", SERVER_ADDR, SERVER_PORT);
        /* 建立网络连接 */
        ret = mbedtls_net_connect(&ctx, SERVER_ADDR, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
        if (ret != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        /* 配置网络数据发送和接收回调接口 */
        mbedtls_ssl_set_bio(&ssl, &ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");
        /* 执行ssl握手 */
        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)    
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);    /* -0x50:MBEDTLS_ERR_NET_CONN_RESET */
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");
        if ((ret = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            memset(buf, 0, sizeof(buf));
            mbedtls_x509_crt_verify_info((char*)buf, sizeof(buf), "  ! ", ret);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else 
        {
            ESP_LOGI(TAG, "Certificate verified.");
        }
        ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

        /* 发送HTTP请求 */
        ESP_LOGI(TAG, "Writing HTTP request...");
        size_t written_bytes = 0;
        do {
            ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *)GET_REQUEST + written_bytes,
                                    strlen(GET_REQUEST) - written_bytes);
            if (ret >= 0) 
            {
                ESP_LOGI(TAG, "%d bytes written", ret);
                written_bytes += ret;
            } 
            else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) 
            {
                ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
                goto exit;
            }
        } while(written_bytes < strlen(GET_REQUEST));

        /* 读取HTTP回应 */
        ESP_LOGI(TAG, "Reading HTTP response...");
        do
        {
            len = sizeof(buf) - 1;
            memset(buf, 0, sizeof(buf));  
            /* 读取ssl应用数据 */      
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)   /* 对端通知连接即将关闭 */
            {
                ESP_LOGI(TAG, "connection is going to be closed");
                goto exit;
            }
            if (ret < 0)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)   /* 对端通知连接即将关闭 */
                {
                    ESP_LOGI(TAG, "connection is going to be closed");
                }
                goto exit;
            }
            else if (ret == 0)
            {
                ESP_LOGI(TAG, "connection closed");
                goto exit;
            }        
        } while (1);
        len = ret;
        ESP_LOGI(TAG, "%d bytes read:\n%s", len, buf);
        /* 通知服务器连接即将关闭 */
        mbedtls_ssl_close_notify(&ssl);    

    exit:
        /* 释放网络结构体 */
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&ctx);

        ESP_LOGI(TAG, "Completed %d requests", ++request_count);
        for(int countdown = 10; countdown >= 0; countdown--) 
        {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
    }
cleanup:
    /* 释放网络结构体 */
    mbedtls_net_free(&ctx);
    /* 释放ssl结构体 */
    mbedtls_ssl_free(&ssl);
    /* 释放ssl配置结构体 */
    mbedtls_ssl_config_free(&conf);
    /* 释放随机数结构体 */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    /* 释放熵结构体 */
    mbedtls_entropy_free(&entropy);
    /* 释放x509证书结构体 */
    mbedtls_x509_crt_free(&cert);    
}

/**
 ***********************************************************************************************************************
 * @brief           tls客户端初始化
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
int app_tls_client_init(void)
{
    xTaskCreate((TaskFunction_t )tls_client_task,
                (const char*    )"tls_client_task",
                (uint16_t       )TLS_CLIENT_TASK_STK_SIZE,
                (void*          )NULL,
                (UBaseType_t    )TLS_CLIENT_TASK_PRIO,
                (TaskHandle_t*  )&tls_client_task_handler);    

    return 0;
}