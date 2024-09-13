/**********************************************
 * File:    ssl_client.cc
 * Author:  [Author Name]
 *
 * Description:
 *   Implements SSL hanshake using RSA/DHE on 
 *   the client
 **********************************************/

/* Includes */
#include <iomanip>
#include <iostream>
#include <sstream>
#include "base64.h"
#include "channels.h"
#include "cryptlib.h"
#include "crypto_adaptor.h"
#include "dh.h"
#include "elgamal.h"
#include "files.h"
#include "filters.h"
#include "hex.h"
#include "hkdf.h"
#include "hmac.h"
#include "integer.h"
#include "logger.h"
#include "osrng.h"
#include "rsa.h"
#include "secblock.h"
#include "sha.h"
#include "ssl_client.h"
#include "stdlib.h"
#include "string.h"
#include "tcp.h"
#include "utils.h"

/* Namespaces */
using namespace std;
using namespace CryptoPP;

// Create a random number generator ('randomizer') with automatic seeding for secure random number generation.
AutoSeededRandomPool randomizer;

// Print the hexadecimal representation of the input string.
void printStringInHex(const std::string& str) 
{
  std::cout << "c: Pre-Master Secret : ";
  for (size_t i = 0; i < str.length(); i++) 
  {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(static_cast<unsigned char>(str[i]));
  }
  std::cout << std::endl;
}

//Compare received server certificate with the expected server certificate for validation.
bool validate_cert(string rx_server_cert, string rx_server_pk, string server_cert) 
{
  return (rx_server_cert == server_cert);
}

//Constructor for SSL client initializes a timestamped logger and attaches it to the TCP connection.
SslClient::SslClient() 
{
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0) exit(1);

  this->logger_ = new Logger(("ssl_client_" + datetime + ".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Client Log at " + datetime);
}

// SSL client destructor: deletes logger and detaches from TCP connection.
SslClient::~SslClient() 
{
  if (this->logger_) 
  {
    delete this->logger_;
    this->logger_ = NULL;
    this->tcp_->set_logger(NULL);
  }
}

// Connects to IP and port using TCP socket. Returns 0 on success, -1 on failure.
int SslClient::connect(const string& ip, int port, uint16_t connection_type) 
{
  if (this->tcp_->socket_connect(ip, port) != 0) 
  {
    cerr << "Couldn't connect" << endl;
    return -1;
  }

// Hardcoded certificate values simulate SSL handshake due to absence of third-party validation.
  string server_cert =
      "db6dd87c3f12312872c3b2b653becb281cf2f4c22e256b95b2dcaffed19562f3";
  string client_cert =
      "cd5a1c33684c1a691ee97f1014a35db2858d5632a4fccb74711bb883425f549f";

//~~~~~~~~~~~~~~~~~~~~~~~~SENDING CLIENT HELLO~~~~~~~~~~~~~~~~~~~~~//

//Determines chosen key exchange algorithm based on provided connection type.

  uint8_t chosen_keyExchange;

  if (connection_type == SSL::KE_RSA) 
  {
    cout << "c: RSA IMPLEMENTATION " << endl;
    chosen_keyExchange = SSL::KE_RSA;
  } 
  else if (connection_type == SSL::KE_DHE) 
  {
    cout << "c: DHE IMPLEMENTATION " << endl;
    chosen_keyExchange = SSL::KE_DHE;
  }

//Serialize message type to hexadecimal string for hello handshake.
  uint8_t messageType = SSL::HS_CLIENT_HELLO;
  stringstream hexStream;
  hexStream << hex << setw(2) << setfill('0') << static_cast<int>(messageType);
  string hex_stringdh = hexStream.str();

//Serialize key exchange type and generate client random data block.
  stringstream hexStream1;
  hexStream1 << hex << setw(2) << setfill('0') << static_cast<int>(chosen_keyExchange);
  string hex_stringdh1 = hexStream1.str();

  SecByteBlock clientRandomDataBlock(32);
  randomizer.GenerateBlock(clientRandomDataBlock, 32);

// Encode client random data block to Base64 format.
  CryptoPP::Base64Encoder base64Encoder;
  string clientRandomBase64Str1;
  base64Encoder.Attach(new CryptoPP::StringSink(clientRandomBase64Str1));
  base64Encoder.Put(clientRandomDataBlock.data(), clientRandomDataBlock.size());
  base64Encoder.MessageEnd();

  string clientRandomStr1(
      reinterpret_cast<const char*>(clientRandomDataBlock.data()),
        clientRandomDataBlock.size());

//Construct and send handshake packet with type, version, and client random data.
  Record handshakePacket;
  handshakePacket.hdr.type = REC_HANDSHAKE;
  handshakePacket.hdr.version = VER_99;
  string mergedBody = hex_stringdh + hex_stringdh1 + clientRandomBase64Str1;
  char* recordData1 = (char*)malloc(mergedBody.length() * sizeof(char));
  memcpy(recordData1, mergedBody.c_str(), mergedBody.length());
  handshakePacket.data = recordData1;
  handshakePacket.hdr.length = mergedBody.length();
  this->send(handshakePacket);
  free(recordData1);

//~~~~~~~~~~~~~~~~~~~~~~SERVER HELLO RECEIVED~~~~~~~~~~~~~~~~~~~~~~//
  
// Retrieve and parse data from the received handshake record.
// Extract cipher type and server random data encoded in Base64 format. 
  Record recv_recorddh;
  this->recv(&recv_recorddh);

  string temp_buffer = recv_recorddh.data;

  temp_buffer = temp_buffer.substr(0, recv_recorddh.hdr.length);

  int rx_cipher_type = stoi(temp_buffer.substr(2, 2), nullptr, 16);

  temp_buffer = temp_buffer.substr(0, recv_recorddh.hdr.length);

  string serverRandomBase64 = temp_buffer.substr(4, 45);

// Decode Base64-encoded server random data.
  Base64Decoder decoder;
  decoder.Put(reinterpret_cast<const byte*>(serverRandomBase64.data()),
              serverRandomBase64.size());
  decoder.MessageEnd();

//Convert decoded server random data to string and verify received cipher type.
  SecByteBlock decodedServerRandomBlock(32);
  size_t decodedSize = decoder.MaxRetrievable();
  if (decodedSize) 
  {
    decodedServerRandomBlock.resize(decodedSize);
    decoder.Get(decodedServerRandomBlock.data(),
                decodedServerRandomBlock.size());
  }

  string serverRandomStr1(
      reinterpret_cast<const char*>(decodedServerRandomBlock.data()),
      decodedServerRandomBlock.size());

  if (rx_cipher_type == SSL::KE_DHE || rx_cipher_type == SSL::KE_RSA) 
  {
    cout << "c: CLIENT AFFIRMATIVE" << endl;
  }

// Check if the connection type is RSA.
  if (connection_type == SSL::KE_RSA) 
  {
//~~~~~~~~~~~~~~~~~RECIEVING PUBLIC KEY FROM THE SERVER~~~~~~~~~~~~~~~~//
    Record recv_record;
    this->recv(&recv_record);

//~~~~~~~~~~~~~~~~~~~~~~RECEVING SERVER HELLO DONE~~~~~~~~~~~~~~~~~~~~~//

// Extract Base64-encoded public key from received record data.
    temp_buffer = recv_record.data;
    temp_buffer = temp_buffer.substr(0, recv_record.hdr.length);
    string base64PublicKeyString = temp_buffer.substr(2);

    string publicKeyString;

// Decode the Base64-encoded public key.
    StringSource(base64PublicKeyString, true,
                 new Base64Decoder(new StringSink(publicKeyString)));

// Decode the DER-encoded public key.
    RSA::PublicKey publicKey;
    StringSource publicKeySource(publicKeyString, true);
    publicKey.BERDecodePublicKey(publicKeySource, true /* parametersPresent */,
                                 publicKeyString.size());

//~~~~~~~~~~~~~~~~~~~RECIEVING CERTIFICATE FROM THE SERVER~~~~~~~~~~~~~~~~~~~~~~//
    Record recv_record_cert;
    this->recv(&recv_record_cert);

// Base64-encoded public key.
    temp_buffer = recv_record_cert.data;
    temp_buffer =
        temp_buffer.substr(0, recv_record_cert.hdr.length);
    string server_cert_rsa = temp_buffer.substr(2);

    cout << "c: Server Certificate : " << server_cert_rsa << endl;

    if (validate_cert(server_cert_rsa, publicKeyString, server_cert))
      cout << "c: Server certificate validation successful" << endl;
    else
      cout << "c: Server certificate validation failed" << endl;


//~~~~~~~~~~~~~~~~~~RECEVING SERVER HELLO DONE~~~~~~~~~~~~~~~~~~~~~//

    Record receivedDataBlock;
    this->recv(&receivedDataBlock);

    temp_buffer = receivedDataBlock.data;
    temp_buffer =
        temp_buffer.substr(0, receivedDataBlock.hdr.length);

    int rx_msg_type = stoi(temp_buffer.substr(0, 2), nullptr, 16);

    if (rx_msg_type != SSL::HS_SERVER_HELLO_DONE) 
    {
      cerr << " Server hello message was not successfully received ";
      return 1;
    }

//Generate premaster secret using a random block of appropriate size.
    SecByteBlock premasterSecret(32);
    AutoSeededRandomPool randomizer;
    randomizer.GenerateBlock(premasterSecret, premasterSecret.size());

// Convert the premaster secret to a string and prepare plaintext for encryption.
    string premasterSecretStr(
        reinterpret_cast<const char*>(premasterSecret.data()),
        premasterSecret.size());
    string plaintext = premasterSecretStr;  
    string ciphertext;                      

// Encrypt plaintext using public key.
// Encode ciphertext to Base64 format.
// Print premaster secret in hexadecimal.
    if (rsa_encrypt(publicKey, &ciphertext, plaintext) == 0) 
    {
      string base64EncodedCiphertext;

      StringSource ss(ciphertext, true,
                      new Base64Encoder(new StringSink(base64EncodedCiphertext),
                                        false));

      printStringInHex(premasterSecretStr);

//~~~~~~~~~~~~~~~~~~~CLIENT SENDS ITS KEY EXCHANGE MESSAGE (ATTACH)~~~~~~~~~~~~~~~~~//

      uint8_t clientExchangeType = SSL::HS_CLIENT_KEY_EXCHANGE;
      stringstream streamc1;
      streamc1 << hex << setw(2) << setfill('0')
               << static_cast<int>(clientExchangeType);
      string hex_stringc2 = streamc1.str();

    

//Send handshake message if encryption succeeds, otherwise print error.
      Record messageToSend;
      messageToSend.hdr.type = REC_HANDSHAKE;
      messageToSend.hdr.version = VER_99;
      string body1 = hex_stringc2 + base64EncodedCiphertext;
      char* dataBuf = (char*)malloc(body1.length() * sizeof(char));
      memcpy(dataBuf, body1.c_str(), body1.length());
      messageToSend.data = dataBuf;
      messageToSend.hdr.length = body1.length();
      this->send(messageToSend);
      free(dataBuf);

    } 
    else 
    {
      cerr << "Encryption failed" << endl;
    }

    SecByteBlock derivedKey;
    derivedKey.resize(16);

// Desired size of the derived keys in bytes
    size_t keySize = 16;  

// For deriving client key from premaster.
    SecByteBlock clientKey1(keySize);

//~~~~~~~~~~~~~~~~~~~~~DERIVE KEY~~~~~~~~~~~~~~~~~~~~~~~~~~~//

// Form cryptographic seed by concatenating server and client random data.
    SecByteBlock seed(decodedServerRandomBlock.size() +
                      clientRandomDataBlock.size());
    memcpy(seed.data(), decodedServerRandomBlock.data(),
           decodedServerRandomBlock.size());
    memcpy(seed.data() + decodedServerRandomBlock.size(),
           clientRandomDataBlock.data(), clientRandomDataBlock.size());

// Derive client key using HKDF with SHA-256 from premaster secret and seed, and set it as the shared key.
    HKDF<SHA256>().DeriveKey(clientKey1.data(), clientKey1.size(),
                             premasterSecret.data(), premasterSecret.size(),
                             seed.data(), seed.size(),
                             reinterpret_cast<const byte*>("key expansion"),
                             strlen("key expansion"));

    string clientKeyStr1(reinterpret_cast<const char*>(clientKey1.data()),
                         clientKey1.size());

    this->set_shared_key(clientKey1.data(), clientKey1.size());
  }

// Check if the connection type is DHE.
  if (connection_type == SSL::KE_DHE) 
  {
  
// Setting P, G, and Q values for Diffie-Hellman key exchange.
// Extracting values from concatenated string.

    AutoSeededRandomPool RandoGen;
    Integer dh_p_1(temp_buffer.substr(49, 257).c_str());
    Integer dh_q_1(temp_buffer.substr(306, 257).c_str());
    Integer dh_g_1(temp_buffer.substr(563, 2).c_str());

    DH clientDH;
    clientDH.AccessGroupParameters().Initialize(dh_p_1, dh_q_1, dh_g_1);

//~~~~~~~~~~~~~~~~~~~RECIVING PUBLIC KEY FROM THE SERVER~~~~~~~~~~~~~~~~~~~~~~~~//

    Record receivedDataPacketDHpk;
    this->recv(&receivedDataPacketDHpk);
    temp_buffer = receivedDataPacketDHpk.data;
    temp_buffer =
        temp_buffer.substr(0, receivedDataPacketDHpk.hdr.length);


//~~~~~~~~~~~~~~~~~~~~~GENERATING MASTER SECRET KEY~~~~~~~~~~~~~~~~~~~~~~~~~~~//

    string srvPubKeyStr;
    CryptoPP::StringSink stringSink(srvPubKeyStr);
    CryptoPP::StringSource(
        temp_buffer.substr(2), true,
        new CryptoPP::Base64Decoder(new CryptoPP::Redirector(stringSink)));

    CryptoPP::SecByteBlock srvPublicKey(
        reinterpret_cast<const unsigned char*>(srvPubKeyStr.data()),
        srvPubKeyStr.size());

//~~~~~~~~~~~~~~~~~RECIEVING CERTIFICATE FROM THE SERVER~~~~~~~~~~~~~~~~~~~~~~//
    Record certificateRecordDHE;
    this->recv(&certificateRecordDHE);

// Base64-encoded public key.
    string temp_buffer1 = certificateRecordDHE.data;
    temp_buffer1 =
        temp_buffer1.substr(0, certificateRecordDHE.hdr.length);
    string server_cert_dhe = temp_buffer1.substr(2);

    cout << "c: Server Certificate : " << server_cert_dhe << endl;

    if (validate_cert(server_cert_dhe, srvPubKeyStr, server_cert))
      cout << "c: Server certificate validation successful" << endl;
    else
      cout << "c: Server certificate validation failed" << endl;

//~~~~~~~~~~~~~~~~~~~~~RECEVING SERVER HELLO DONE~~~~~~~~~~~~~~~~~~~~~~~~~~~//

    Record receivedDataBlock;
    this->recv(&receivedDataBlock);
    temp_buffer = receivedDataBlock.data;
    temp_buffer =
        temp_buffer.substr(0, receivedDataBlock.hdr.length);

// Generate client's private and public keys.
    SecByteBlock privateKey(clientDH.PrivateKeyLength());
    SecByteBlock publicKey(clientDH.PublicKeyLength());
    clientDH.GenerateKeyPair(randomizer, privateKey, publicKey);

//~~~~~~~~~~~~~~~~~~~~SENDING PUBLIC KEY TO THE SERVER~~~~~~~~~~~~~~~~~~~~~//

// Encode the public key as a base64 string.
    string public_key_str;
    StringSink sink(public_key_str);
    ArraySource(publicKey.data(), publicKey.size(), true,
                new Base64Encoder(new Redirector(sink),
                                  false /* do not insert line breaks */));

//~~~~~~~~~~~~~~~~~CLIENT SENDS ITS KEY EXCHANGE MESSAGE (ATTACH)~~~~~~~~~~~~~~~~~//

    uint8_t exchangeType = SSL::HS_CLIENT_KEY_EXCHANGE;
    stringstream exchangeStream;
    exchangeStream << hex << setw(2) << setfill('0')
              << static_cast<int>(exchangeType);
    string hex_stringc22 = exchangeStream.str();

    Record outgoingHandshakeRecord;
    outgoingHandshakeRecord.hdr.type = REC_HANDSHAKE;
    outgoingHandshakeRecord.hdr.version = VER_99;
    string dataBlock = hex_stringc22 + public_key_str;
    char* transData = (char*)malloc(dataBlock.length() * sizeof(char));
    memcpy(transData, dataBlock.c_str(), dataBlock.length());
    outgoingHandshakeRecord.data = transData;
    outgoingHandshakeRecord.hdr.length = dataBlock.length();
    this->send(outgoingHandshakeRecord);
    free(transData);
  

//~~~~~~~~~~~~~~~~~~~~SENDING CLIENT CERTIFICATE TO THE SERVER~~~~~~~~~~~~~~~~~~~~//

    uint8_t clientCertType = SSL::HS_CERTIFICATE;
    stringstream clientCertStream;
    clientCertStream << hex << setw(2) << setfill('0')
                   << static_cast<int>(clientCertType);
    string hex_stringcertdhe = clientCertStream.str();

    Record DHECertRecord;
    DHECertRecord.hdr.type = REC_HANDSHAKE;
    DHECertRecord.hdr.version = VER_99;
    string certBody = hex_stringcertdhe + client_cert;
    char* certData = (char*)malloc(certBody.length() * sizeof(char));
    memcpy(certData, certBody.c_str(), certBody.length());
    DHECertRecord.data = certData;
    DHECertRecord.hdr.length = certBody.length();
    this->send(DHECertRecord);
    free(certData);

    SecByteBlock preMasterSecret(clientDH.AgreedValueLength());

// Encode the public key as a base64 string.
    string premaster;
    StringSink sink1(premaster);
    ArraySource(preMasterSecret.data(), preMasterSecret.size(), true,
                new Base64Encoder(new Redirector(sink1),
                                  false /* do not insert line breaks */));

    if (!clientDH.Agree(preMasterSecret, privateKey, srvPublicKey)) 
    {
      cerr << "Client: Failed to reach the pre-master secret agreement" << endl;
    }

// Desired size of the derived keys in bytes. 
    size_t keySize = 16;  

    SecByteBlock clientKey(keySize);
    SecByteBlock seed(decodedServerRandomBlock.size() +
                      clientRandomDataBlock.size());
    memcpy(seed.data(), decodedServerRandomBlock.data(),
           decodedServerRandomBlock.size());
    memcpy(seed.data() + decodedServerRandomBlock.size(),
           clientRandomDataBlock.data(), clientRandomDataBlock.size());

// Generate client key with HMAC-SHA256-based HKDF using pre-master secret and seed.
    HKDF<SHA256>().DeriveKey(clientKey.data(), clientKey.size(),
                             preMasterSecret.data(), preMasterSecret.size(),
                             seed.data(), seed.size(),
                             reinterpret_cast<const byte*>("key expansion"),
                             strlen("key expansion"));

    string clientKeyStr(reinterpret_cast<const char*>(clientKey.data()),
                        clientKey.size());

    this->set_shared_key(clientKey.data(), clientKey.size());
    printStringInHex(clientKeyStr);
  }

//~~~~~~~~~~~~~~~~~~~~~CLIENT FINISHED MESSAGE~~~~~~~~~~~~~~~~~~//
  uint8_t endMessageType = SSL::HS_FINISHED;
  stringstream finStream;
  finStream << hex << setw(2) << setfill('0') << static_cast<int>(endMessageType);
  string finHexStream = finStream.str();

  Record endRecord;
  endRecord.hdr.type = REC_HANDSHAKE;
  endRecord.hdr.version = VER_99;
  char* finData = (char*)malloc(finHexStream.length() * sizeof(char));
  memcpy(finData, finHexStream.c_str(), finHexStream.length());
  endRecord.data = finData;

  endRecord.hdr.length = finHexStream.length();
  this->send(endRecord);
  free(finData);
  
  return 1;

}

// Close the SSL client connection by closing the underlying TCP socket and return the status code.
int SslClient::close() 
{
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}