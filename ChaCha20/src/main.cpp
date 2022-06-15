#include <Arduino.h>
#include <ChaCha.h>
#include <Crypto.h>
#include <string.h>
#include <pgmspace.h>

#define MAX_PLAINTEXT_SIZE 16
#define MAX_CIPHERTEXT_SIZE 16

//Declaración de estructura
struct TestVector
{
    const char *name;
    byte key[32];
    size_t keySize;
    uint8_t rounds;
    byte plaintext[MAX_PLAINTEXT_SIZE];
    byte ciphertext[MAX_CIPHERTEXT_SIZE];
    byte iv[8];
    byte counter[8];
    size_t size;
};

//Asignar valores al vector
TestVector VectorChaCha20_128 = 
{
    .name        = "ChaCha20 128-bit",
    .key         = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    .keySize     = 16,
    .rounds      = 20,
    .plaintext   = {0x45, 0x6C, 0x20, 0x4D, 0x65, 0x6E, 0x63, 0x68, //Texto a encriptar
                    0x6F, 0x20, 0x6D, 0x70, 0x6C, 0x76, 0x21, 0x21},
    .ciphertext  = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},//Relleno para evitar problemas 
    .iv          = {101,102,103,104,105,106,107,108},
    .counter     = {109, 110, 111, 112, 113, 114, 115, 116},
    .size        = 16
};

//Declaraciones extra que no se que hacen pero se incluyen
TestVector testVector;
ChaCha chacha;
byte bufferByte[16];
String bufferStr[16];

//Declaración de funciones
void setValues(ChaCha *cipher, struct TestVector *test);      //Inicializa valores para encriptar y desencriptar
void encryptCipher(ChaCha *cipher, struct TestVector *test);  //Encripta
void decryptCipher(ChaCha *cipher, struct TestVector *test);  //Descifra
void byteToStr16(byte *input, char *output);                  //Convierte arreglo de byte a String de 16
void strToByte16(String input, byte *output);                  //Convierte string a un arreglo de 16 bytes


void setup() 
{
  Serial.begin(115200);
  Serial.println();

  Serial.print("State size...");
  Serial.println(sizeof(ChaCha));
  Serial.println();
  Serial.setTimeout(15000);

  Serial.print("Prueba ingresando string en consola\n");

  Serial.print("Ingresa texto a encriptar: ");
  
  strToByte16(Serial.readString(), bufferByte);   //Convierte string en consola a bytes

  memcpy(VectorChaCha20_128.plaintext, bufferByte, 16);   //El byte se pasa al vector
  
  //NOTA: si se encripto o descifro con anterioridad hay que volver a 
  //inicializar los valores con setValues
  setValues(&chacha, &VectorChaCha20_128);
  encryptCipher(&chacha, &VectorChaCha20_128);

  //Por ejemplo, en este caso
  setValues(&chacha, &VectorChaCha20_128);
  decryptCipher(&chacha, &VectorChaCha20_128);

}

void loop() 
{
  // put your main code here, to run repeatedly:
}

void setValues(ChaCha *cipher, struct TestVector *test)
{
  //Protocolos a seguir de ChaCha, deben ser en este orden
  cipher -> setNumRounds(test -> rounds);
  cipher -> setKey(test -> key, test -> keySize);
  cipher -> setIV(test -> iv, cipher -> ivSize());
  cipher -> setCounter(test -> counter, 8);
}

void encryptCipher(ChaCha *cipher, struct TestVector *test)
{
  byte output[MAX_CIPHERTEXT_SIZE];
  size_t posn, len;

  Serial.print("texto original: \n");

    for (int i = 0; i < test -> size; i++)
    {
      Serial.write(test -> plaintext[i]);   //Mensaje a encriptar en la consola
    }
      Serial.println();


    Serial.print("texto encriptado: \n");

    //Proceso de encriptacion
    for (posn = 0; posn < test->size; posn++) 
    {
        len = test->size - posn;
        if (len > 1)
            len = 1;
        cipher->encrypt(output + posn, test->plaintext + posn, len);
        test -> ciphertext[posn] = output[posn];
        Serial.write(output[posn]);        //Escribe cifrado en la consola
    }
    Serial.println();
}

void decryptCipher(ChaCha *cipher, struct TestVector *test)
{
  byte output[MAX_CIPHERTEXT_SIZE];
  size_t posn, len;

  Serial.print("texto desencriptado: \n");
    for (posn = 0; posn < test -> size; posn++) {
        len = test->size - posn;
        if (len > 1)
            len = 1;
        cipher->decrypt(output + posn, test -> ciphertext + posn, len);
        Serial.write(output[posn]);
    }
        Serial.println();
}

void byteToStr16(byte *input, char *output)
{
  int lenght = sizeof(input);      //Longitud del arreglo
  memcpy(output, input, lenght);   //Convierte los bytes a String
}                  


void strToByte16(String input, byte *output)
{
  int length = sizeof(input);     //Longitud del string
  char temp[16];                  //memcpy no funciona con string, así que se usa char temporal
  if (length < 16)
  {
    for (int i = length; i < 16; i++)
      *(output + i) = ' ';          //Agrega espacios en blanco en caso de que el string sea menor a 16 
  }

  else if (length > 16)
  length = 16;                    //Recorta la cadena a 16

  for (int j = 0; j < length; j++)
    *(temp + j) = input[j];
  memcpy(output, temp, length);     //Convierte str a byte
}