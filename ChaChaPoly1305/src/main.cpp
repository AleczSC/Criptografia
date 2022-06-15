#include <Arduino.h>
#include <Crypto.h>
#include <ChaChaPoly.h>
#include <string.h>
#include <pgmspace.h>

#define MAX_PLAINTEXT_LEN 265

//Declaración de la estructura
struct TestVector
{
    const char *name;
    uint8_t key[32];
    uint8_t plaintext[MAX_PLAINTEXT_LEN];
    uint8_t ciphertext[MAX_PLAINTEXT_LEN];
    uint8_t authdata[16];
    uint8_t iv[16];
    uint8_t tag[16];
    size_t authsize;
    size_t datasize;
    size_t tagsize;
    size_t ivsize;
};

//Asignar valores al vector
TestVector testVectorChaChaPoly
{
  .name        = "ChaChaPoly #1",
  .key         = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f},
  .plaintext   = {0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
                  0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
                  0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
                  0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
                  0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
                  0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
                  0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
                  0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
                  0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
                  0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
                  0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
                  0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
                  0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
                  0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
                  0x74, 0x2e},
  .ciphertext  = {0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
                  0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
                  0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
                  0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
                  0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
                  0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
                  0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                  0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
                  0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
                  0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
                  0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
                  0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
                  0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
                  0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                  0x61, 0x16},
  .authdata    = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
                  0xc4, 0xc5, 0xc6, 0xc7},
  .iv          = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
                  0x44, 0x45, 0x46, 0x47},
  .tag         = {0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
                  0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91},
  .authsize    = 12,
  .datasize    = 114,
  .tagsize     = 16,
  .ivsize      = 12
};

ChaChaPoly chachapoly;

//Declaración de funciones
void setValuesChaChaPoly(ChaChaPoly *cipher, TestVector *test);
void encryptCipherChaChaPoly(ChaChaPoly *cipher, TestVector *test);
void decryptCipherChaChaPoly(ChaChaPoly *cipher, TestVector *test);


void setup()
{
  Serial.begin(115200);
  Serial.println();

  Serial.print("State Size ... ");
  Serial.println(sizeof(ChaChaPoly));
  Serial.println();

  encryptCipherChaChaPoly(&chachapoly, &testVectorChaChaPoly);
  decryptCipherChaChaPoly(&chachapoly, &testVectorChaChaPoly);

}

void loop() {
  // put your main code here, to run repeatedly:
}


void setValuesChaChaPoly(ChaChaPoly *cipher, TestVector *test)
{
  size_t posn, len;

  cipher -> clear();      //Limpiar valores

  //Comienza configuracion, debe ejecutarse en este orden
  cipher -> setKey(test -> key, 32);
  cipher -> setIV(test -> iv, test -> ivsize);

  //Generacion de autenticacion
  Serial.print("Authentication data: ");
  for (posn = 0; posn < test -> authsize; posn++) 
  {
    len = test->authsize - posn;
    if (len > 1)
      len = 1;
    cipher->addAuthData(test->authdata + posn, len);
    Serial.write(test -> authdata[posn]);
  }
  Serial.print("\n\n");

}

void encryptCipherChaChaPoly(ChaChaPoly *cipher, TestVector *test)
{
  byte output[MAX_PLAINTEXT_LEN];
  size_t posn, len;

  //Inicializar valores para encriptacion
  setValuesChaChaPoly(cipher, test);

  //Imprimir texto a encriptar en la consola
  Serial.print("Texto a original: ");
  for (posn = 0; posn < test -> datasize; posn++)
    Serial.write(test -> plaintext[posn]);
  Serial.print("\n\n");

  //Comienza encriptacion
  Serial.print("Texto encriptado: ");
  for (posn = 0; posn < test -> datasize; posn++) 
  {
    len = test->datasize - posn;
    if (len > 1)
        len = 1;
    cipher->encrypt(output + posn, test->plaintext + posn, len);//
    test -> ciphertext[posn] = output[posn];                    //Guardar palabra encriptada en la estructura
    Serial.write(output[posn]);
  }
  Serial.print("\n\n");

  //Generacion de tag
  cipher -> computeTag(test -> tag, sizeof(test -> tag));
  //Imprimir tag en la consola
  Serial.print("Tag generada: ");
  for (int i = 0; i < sizeof(test -> tag); i++)
    Serial.write(test -> tag[i]);
  Serial.print("\n\n");
}

void decryptCipherChaChaPoly(ChaChaPoly *cipher, TestVector *test)
{
  byte output[MAX_PLAINTEXT_LEN];
  size_t posn, len;

  //Inicializar valores para descifrar
  setValuesChaChaPoly(cipher, test);

  //Proceso de descifrado 
  Serial.print("texto desencriptado: \n");
  for (posn = 0; posn < test -> datasize; posn++) 
  {
    len = test -> datasize - posn;
    if (len > 1)
      len = 1;
    cipher->decrypt(output + posn, test -> ciphertext + posn, len);
    Serial.write(output[posn]);
  }
  Serial.print("\n\n");

  //Comprobar tag
  if (cipher -> checkTag(test -> tag, sizeof(test -> tag)))
    Serial.print("Tag comprobada exitosamente. \n\n");
  else
    Serial.print("Error: la Tag no coincide. \n\n");   
}