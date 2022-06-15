#include <Arduino.h> 
#include <WiFi.h>
#include <PubSubClient.h>
#include "mbedtls/aes.h"

char * key = "abcdefghijklmnop"; 
#define BUILTIN_LED  2
//CONFIGURAMOS ACCESO A WIFI//
const char* ssid     = "virus peligroso";
const char* password = "nomelase"; 

const char *mqtt_server = "52.23.115.184";
const int mqtt_port = 1883;
const char *mqtt_user = "web_client";
const char *mqtt_pass = "121212";
//CONFIGURAMOS MQTT LIBRERIA//
WiFiClient espClient;
PubSubClient client(espClient);
mbedtls_aes_context aes; // Declaramos objeto

//ASIGNAMOS VARIABLES
long lastMsg = 0;
char msg[40];
char msg1[129];



//*** DECLARACION FUNCIONES ***
void setup_wifi();
void reconnect();
int GET_THE_RSSI();
void GET_THE_GPS(float *longitud, float *latitud);
String Cifrado_AES128(String mensaje_cifrar);

void setup() {
  pinMode(BUILTIN_LED, OUTPUT);
  Serial.begin(115200);
  randomSeed(micros());
  setup_wifi();
  client.setServer(mqtt_server, mqtt_port);
  
  Serial.begin(115200); 


}
  
void loop() {
// EMPIEZA EL CHECKEO MQTT
	if (!client.connected()) {
		reconnect();
	}
// TERMINA EL CHECKEO
	client.loop();
    

	long now = millis();
	if (now - lastMsg > 500){
		lastMsg = now;

		//////// GET THE DATA //////////////////////
		/// GET THE RSSI ///
		int RSSI = GET_THE_RSSI(); 
		/// GET THE GPS ///
		float lon = 0;
		float lat =0;
		GET_THE_GPS(&lon,&lat);
		// ALERT MESSAGE //
		String msg_alert = "1";
		// CREATE THE STRING //
		String to_send = "RSSI:" + String(RSSI) + "," +  "lon:" + String(lon) + "," +  "lat:" + String(lat) +  "Alert:"+ msg_alert ;
		to_send.toCharArray(msg, 40);
		Serial.print("Publicamos Mensaje No seguro -> "); 
		Serial.println(msg);
		client.publish("msj_no_seguro", msg);

    // Enviando informacion cifrada //RSSI:15, lon:123.12345, lat:123.12345, Alert:1;

    String Intensidad_Senal = "RSSI:" + String(RSSI) + ",";
    String Longitud = "lon:" + String(lon)+ ",";
    String Latitud = "lat:" + String(lat)+ ",";
    String Etiqueta_Alerta = "Alert:"+ (msg_alert) ;

    String CYPHED_Intensidad_Senal = Cifrado_AES128(Intensidad_Senal);
    Serial.print("CYPHED_Intensidad_Senal= ");
    Serial.println(CYPHED_Intensidad_Senal);
    String CYPHED_Longitud = Cifrado_AES128(Longitud);
    Serial.print("CYPHED_Longitud= ");
    Serial.println(CYPHED_Longitud);
    String CYPHED_Latitud = Cifrado_AES128(Latitud);
    Serial.print("CYPHED_Latitud= ");
    Serial.println(CYPHED_Latitud);
    String CYPHED_Etiqueta_Alerta = Cifrado_AES128(Etiqueta_Alerta);
    Serial.print("CYPHED_Etiqueta_Alerta= ");
    Serial.println(CYPHED_Etiqueta_Alerta);

    // Publicando String Cifrado completo // 

    String FullCyphedMsg = CYPHED_Intensidad_Senal + CYPHED_Longitud + CYPHED_Latitud + CYPHED_Etiqueta_Alerta;
    Serial.println("String Completo -> " );

    Serial.println(FullCyphedMsg);
    FullCyphedMsg.toCharArray(msg1, 129);
		Serial.print("Publicamos Mensaje Seguro!! -> "); 
		Serial.println(msg1);
		client.publish("msj_seguro", msg1);
		delay(1000);
}
}

void setup_wifi(){
	delay(10);
	// Nos conectamos a nuestra red Wifi
	Serial.println();
	Serial.print("Conectando a ");
	Serial.println(ssid);

	WiFi.begin(ssid, password);

	while (WiFi.status() != WL_CONNECTED) {
		delay(500);
		Serial.print(".");
	}

	Serial.println("");
	Serial.println("Conectado a red WiFi!");
	Serial.println("Dirección IP: ");
	Serial.println(WiFi.localIP());
}



void reconnect() {

	while (!client.connected()) {
		Serial.print("Intentando conexión Mqtt...");
		// Creamos un cliente ID
		String clientId = "esp32_";
		clientId += String(random(0xffff), HEX);
		// Intentamos conectar
		if (client.connect(clientId.c_str(),mqtt_user,mqtt_pass)) {
			Serial.println("Conectado!");
			// Nos suscribimos
		} else {
			Serial.print("falló :( con error -> ");
			Serial.print(client.state());
			Serial.println(" Intentamos de nuevo en 5 segundos");

			delay(5000);
		}
	}
}

int GET_THE_RSSI(){
	Serial.println("Getting The RSSI");
    int rssi = random(14, 20);
	delay(100);
	return rssi;
	

}


void GET_THE_GPS(float *longitud, float *latitud){
	Serial.println("Getting The GPS DATA");

    *longitud = random(1, 500) / 100.0;
	*latitud = random(1, 500) / 100.0;

}

String Cifrado_AES128(String mensaje_cifrar){
  
  char *input = "";
 // Lo hace string //
  int string_len = mensaje_cifrar.length() + 1;
  char char_array_mensaje[string_len];  
  mensaje_cifrar.toCharArray(char_array_mensaje,string_len);
  input = char_array_mensaje;
  Serial.print("El input es:");
  Serial.println(input);
  unsigned char output[16]; 
  mbedtls_aes_init( &aes );
  mbedtls_aes_setkey_enc( &aes, (const unsigned char*) key, strlen(key) * 8 );
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)input, output);
  mbedtls_aes_free( &aes );
 
  String data_encrypted = "";
  for (int i = 0; i < 16; i++) {
 
    char str[3];
    
    sprintf(str, "%02x", (int)output[i]);
    data_encrypted = data_encrypted + str;
    //Serial.print(str);
    
  }
  Serial.println("");
  return data_encrypted;
}


