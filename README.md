# mbedTLS ESP32 (ESP-IDF) Server Example

The Example contains a simples mbedTLS server demo.

This example is based on two examples:
  - OpenSSL Server Example from ESP-IDF repo: "https://github.com/espressif/esp-idf/tree/master/examples/protocols/openssl_server"
  - SSL	Server Example from mdebtls repo: "https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_server.c" 

First you should configure the project by "make menuconfig":
  Example Configuration -> 
    1. WIFI SSID: WIFI network to which your PC is also connected to. 
    2. WIFI Password: WIFI password
    
IF you want to test the mbedTLS server demo: 
  1. compile the code and load the firmware 
  2. input the context of "https://192.168.17.128" into your web browser, the IP of your module may not be 192.168.17.128, you should input your module's IP
  3. You may see that it shows the website is not able to be trusted, but you should select that "go on to visit it"
  4. You should wait for a moment until your see the "mbed TLS Test Server!" in your web browser
  5. You can also test the example from "openssl s_client -showcerts -connect 192.168.17.128:443 </dev/null". Don't forget to input your module's IP!
  
Note:
  The private key and certification at the example are not trusted by web browser, because they are not created by CA official, just by ESP-IDF.
  You can alse create your own private key and ceritification by "openssl at ubuntu or others". 
  Espressif has the document "ESP8266_SDKSSL_User_Manual_EN_v1.4.pdf" at "https://www.espressif.com/en/support/download/documents". By it you can gernerate the private key and certification with the fomate of ".pem"
