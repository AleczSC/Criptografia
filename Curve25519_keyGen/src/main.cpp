#include <Arduino.h>
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <TransistorNoiseSource.h>
#include <string.h>

//Variables para el randomizador
#define RNG_TAG "Aleatoriedad"    //Esta etiqueta tambien se considera al momento de generar numeros aleatorios
TransistorNoiseSource noise(36);  //indicar el pin donde se generara el ruido, en mi caso es 36
bool calibrating = false;
bool newCalibrating;

//Definir variables para Diffie-Hellman
uint8_t alice_k[32];
uint8_t alice_f[32];
uint8_t bob_k[32];
uint8_t bob_f[32];

//Buffer para convetir a cadena, tiene un valor extra para el NULL
char bufferChar[33];

//Definir funciones
void calibrarRuido();
void printHEX(uint8_t *input);
void byteToCharArray(byte *input, char *output);


void setup() 
{
  Serial.begin(115200);

  //Inicializar randomizador
  RNG.begin(RNG_TAG);
  RNG.addNoiseSource(noise);

  calibrarRuido();

  //Generar k y f de Alice
  Serial.println("Fase 1 Diffie-Hellman.");
  Serial.println("Generando Alice");
  Curve25519::dh1(alice_k, alice_f);    
  Serial.print("Key publica: ");
  printHEX(alice_k);
  Serial.println("Generando Bob");
  Curve25519::dh1(bob_k, bob_f);
  Serial.print("Key publica: ");
  printHEX(bob_k);

  //Generar el secreto o llave compartida
  Serial.println("Fase 2 Diffie-Hellman");
  Serial.println("Generando secretos compartidos.");
  Curve25519::dh2(bob_k, alice_f);
  Curve25519::dh2(alice_k, bob_f);

  //Comparar los secretos compartidos
  if(memcmp(alice_k, bob_k, 32) == 0)
  {
    Serial.println("Los secretos coinciden.");
    Serial.print("secreto compartido: ");
    printHEX(alice_k);
  }
  else
  {
    Serial.println("Los secretos no coinciden.");
    Serial.print("Secreto alice: ");
    printHEX(alice_k);
    Serial.print("Secreto bob: ");
    printHEX(bob_k);
  }

  //Convertir el arreglo a cadena para enviarse
  byteToCharArray(alice_k, bufferChar);
  Serial.print("Pruebas String.\n");
  Serial.println(bufferChar);
  printHEX((uint8_t *) bufferChar);

}

void loop() {
  // put your main code here, to run repeatedly:
}

void calibrarRuido()
{
  //Asegurarse de que esta calibrado antes de ejecutar el codigo
  while(!calibrating)
  {
    newCalibrating = noise.calibrating();
    if (newCalibrating != calibrating) 
    {
      calibrating = newCalibrating;
      if (calibrating)
        Serial.println("calibrating");
    }
  }
}

void printHEX(uint8_t *input)
{
    static const char hexchars[] = "0123456789ABCDEF";
    for (uint8_t posn = 0; posn < 32; ++posn) 
    {
      Serial.print(hexchars[(input[posn] >> 4) & 0x0F]);
      Serial.print(hexchars[input[posn] & 0x0F]);
    }
    Serial.println();
}

void byteToCharArray(byte *input, char *output)
{
    int len = 32;

    for(int i = 0; i < len; i++)
    {
      output[i] = (char) input[i];
    }
    output[len] = '\0';
}