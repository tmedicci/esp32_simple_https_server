/* mbedTLS server based on OpenSSL server Example from ESP-IDF repository
 * and mbedtls ssl_server example from ARMmbed repository
 *
 *
 * Adapted from the ssl_server example in mbedtls.
 *
 * Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 * Additions Copyright (C) 2018, Tiago Medicci Serrano, All Rights Reserved
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbedtls_server_example.h"


#include <string.h>

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"

#include "nvs_flash.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "https_server.h"
#include "https_server.c"

static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const static int CONNECTED_BIT = BIT0;

const static char *TAG_mbedTLS = "mbedTLS_example";

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

static void mbedtls_example_task(void *p)
{
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
	unsigned char buf[MBEDTLS_EXAMPLE_RECV_BUF_LEN];

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt srvcert;
	mbedtls_pk_context pkey;

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    extern const unsigned char cacert_pem_start[] asm("_binary_cacert_pem_start");
    extern const unsigned char cacert_pem_end[]   asm("_binary_cacert_pem_end");
    const unsigned int cacert_pem_bytes = cacert_pem_end - cacert_pem_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    const unsigned int prvtkey_pem_bytes = prvtkey_pem_end - prvtkey_pem_start;

    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
    ESP_LOGI(TAG_mbedTLS, "SSL server context create ......");
    mbedtls_ssl_init( &ssl );
    ESP_LOGI(TAG_mbedTLS, "OK");
    mbedtls_ssl_config_init( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    /*
	 * 1. Load the certificates and private RSA key
	 */
	mbedtls_printf( "\n  . Loading the server cert. and key..." );

	/*
	 * This demonstration program uses embedded test certificates.
	 * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
	 * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
	 */
	ESP_LOGI(TAG_mbedTLS, "SSL server context set own certification......");
	ESP_LOGI(TAG_mbedTLS, "Parsing test srv_crt......");
	ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) cacert_pem_start,
						cacert_pem_bytes );
	if( ret != 0 )
	{
		ESP_LOGI(TAG_mbedTLS, " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
		goto exit;
	}
    ESP_LOGI(TAG_mbedTLS, "OK");

	ESP_LOGI(TAG_mbedTLS, "SSL server context set private key......");
    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) prvtkey_pem_start,
    						prvtkey_pem_bytes, NULL, 0 );
	if( ret != 0 )
	{
		ESP_LOGI(TAG_mbedTLS, " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
		goto exit;
	}
    ESP_LOGI(TAG_mbedTLS, "OK");

    /*
	 * 2. Setup the listening TCP socket
	 */
	ESP_LOGI(TAG_mbedTLS, "SSL server socket bind at localhost:443 ......");
	if( ( ret = mbedtls_net_bind( &listen_fd, NULL, "443", MBEDTLS_NET_PROTO_TCP ) ) != 0 )
	{
		ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
		goto exit;
	}
	ESP_LOGI(TAG_mbedTLS, "OK");

	/*
	 * 3. Seed the RNG
	 */
	ESP_LOGI(TAG_mbedTLS, "  . Seeding the random number generator..." );
	if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
							   (const unsigned char *) TAG_mbedTLS,
							   strlen( TAG_mbedTLS ) ) ) != 0 )
	{
		ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
		goto exit;
	}
	ESP_LOGI(TAG_mbedTLS, "OK");

    /*
     * 4. Setup stuff
     */
	ESP_LOGI(TAG_mbedTLS, "  . Setting up the SSL data...." );
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
    	ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
    	ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
    	ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

	ESP_LOGI(TAG_mbedTLS, "OK");

reset:
#ifdef MBEDTLS_ERROR_C
	if( ret != 0 )
	{
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		ESP_LOGI(TAG_mbedTLS, "Last error was: %d - %s\n\n", ret, error_buf );
	}
#endif

	mbedtls_net_free( &client_fd );

	mbedtls_ssl_session_reset( &ssl );

	/*
	 * 3. Wait until a client connects
	 */
	ESP_LOGI(TAG_mbedTLS, "  . Waiting for a remote connection ..." );
	if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
									NULL, 0, NULL ) ) != 0 )
	{
		ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
		goto exit;
	}
	mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
	ESP_LOGI(TAG_mbedTLS, "OK");

	/*
	 * 5. Handshake
	 */
	ESP_LOGI(TAG_mbedTLS, "  . Performing the SSL/TLS handshake..." );
	while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
	{
		if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
			goto reset;
		}
	}
	ESP_LOGI(TAG_mbedTLS, "OK");

	/*
	 * 6. Read the HTTP Request
	 */
#ifdef HTTPS_SERVER
	http_server_t server;
	http_server_options_t http_options = HTTP_SERVER_OPTIONS_DEFAULT();

	server = calloc(1, sizeof(*server));
	if (server == NULL) {
		return ESP_ERR_NO_MEM;
	}

	server->port = http_options.port;
	server->start_done = xEventGroupCreate();
	if (server->start_done == NULL) {
		free(server);
		return ESP_ERR_NO_MEM;
	}

	ESP_LOGI(TAG_mbedTLS, "Inicializando http_handle_connection");

    http_handle_connection(server, &ssl);
#else
	ESP_LOGI(TAG_mbedTLS, "  < Read from client:" );
	do
	{
		len = sizeof( buf ) - 1;
		memset( buf, 0, sizeof( buf ) );
		ret = mbedtls_ssl_read( &ssl, buf, len );

		if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
			continue;

		if( ret <= 0 )
		{
			switch( ret )
			{
				case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
					ESP_LOGI(TAG_mbedTLS, " connection was closed gracefully\n" );
					break;

				case MBEDTLS_ERR_NET_CONN_RESET:
					ESP_LOGI(TAG_mbedTLS, " connection was reset by peer\n" );
					break;

				default:
					ESP_LOGI(TAG_mbedTLS, " mbedtls_ssl_read returned -0x%x\n", -ret );
					break;
			}

			break;
		}

		len = ret;
		ESP_LOGI(TAG_mbedTLS, " %d bytes read\n\n%s", len, (char *) buf );

		if( ret > 0 )
			break;
	}
	while( 1 );
#endif
	/*
	 * 7. Write the 200 Response
	 */
	ESP_LOGI(TAG_mbedTLS, "  > Write to client:" );
	len = snprintf( (char *) buf, sizeof(HTTP_RESPONSE) +
					sizeof(mbedtls_ssl_get_ciphersuite( &ssl )) ,HTTP_RESPONSE,
					mbedtls_ssl_get_ciphersuite( &ssl ) );

	while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
	{
		if( ret == MBEDTLS_ERR_NET_CONN_RESET )
		{
			ESP_LOGI(TAG_mbedTLS, " failed\n  ! peer closed the connection\n\n" );
			goto reset;
		}

		if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
			goto exit;
		}
	}

	len = ret;
	ESP_LOGI(TAG_mbedTLS, " %d bytes written\n\n%s\n", len, (char *) buf );

	ESP_LOGI(TAG_mbedTLS, "Closing the connection..." );

	while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
	{
		if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
			ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			ESP_LOGI(TAG_mbedTLS, " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
			goto reset;
		}
	}
	ESP_LOGI(TAG_mbedTLS, "OK");

	ret = 0;
	goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
	if( ret != 0 )
	{
		char error_buf[100];
		mbedtls_strerror( ret, error_buf, 100 );
		ESP_LOGI(TAG_mbedTLS,"Last error was: %d - %s\n\n", ret, error_buf );
	}
#endif

	mbedtls_net_free( &client_fd );
	mbedtls_net_free( &listen_fd );

	mbedtls_x509_crt_free( &srvcert );
	mbedtls_pk_free( &pkey );
	mbedtls_ssl_free( &ssl );
	mbedtls_ssl_config_free( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free( &cache );
#endif
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

    ESP_LOGI(TAG_mbedTLS, "Closing Task");
	vTaskDelete(NULL);
	return ;
} 

static void mbedtls_server_init(void)
{
    int ret;
    xTaskHandle openssl_handle;

    ret = xTaskCreate(mbedtls_example_task,
    				  MBEDTLS_EXAMPLE_TASK_NAME,
					  MBEDTLS_EXAMPLE_TASK_STACK_WORDS,
                      NULL,
					  MBEDTLS_EXAMPLE_TASK_PRIORITY,
                      &openssl_handle); 

    if (ret != pdPASS)  {
        ESP_LOGI(TAG_mbedTLS, "create task %s failed", MBEDTLS_EXAMPLE_TASK_NAME);
    }
}

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        mbedtls_server_init();
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect(); 
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void wifi_conn_init(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(wifi_event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_LOGI(TAG_mbedTLS, "start the WIFI SSID:[%s] password:[%s]\n", EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);
    ESP_ERROR_CHECK( esp_wifi_start() );
}

void app_main(void)
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    wifi_conn_init();
}
