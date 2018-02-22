/* mbedTLS server based on OpenSSL server Example from ESP-IDF repository and mbedtls ssl_server example from ARMmbed repo

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef _MBEDTLS_SERVER_H_
#define _MBEDTLS_SERVER_H_

#include "sdkconfig.h"

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_WIFI_SSID               CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS               CONFIG_WIFI_PASSWORD

#define MBEDTLS_EXAMPLE_TASK_NAME        "mbedtls_example"
#define MBEDTLS_EXAMPLE_TASK_STACK_WORDS 10240
#define MBEDTLS_EXAMPLE_TASK_PRIORITY    8

#define MBEDTLS_EXAMPLE_RECV_BUF_LEN       1024

#define MBEDTLS_EXAMPLE_LOCAL_TCP_PORT     443

#endif

