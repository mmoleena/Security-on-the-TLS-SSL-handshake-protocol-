/**********************************************
 * File:    ssl_server.cc
 * Author:  [Author Name]
 *
 * Description:
 *   Implements SSL hanshake using RSA/DHE on 
 *   the server
 **********************************************/

/* Includes */
#include <stdlib.h>
#include <string.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include "base64.h"
#include "channels.h"
#include "cryptlib.h"
#include "crypto_adaptor.h"
#include "dh.h"
#include "filters.h"
#include "hex.h"
#include "hkdf.h"
#include "integer.h"
#include "logger.h"
#include "osrng.h"
#include "rsa.h"
#include "secblock.h"
#include "sha.h"
#include "ssl_server.h"
#include "tcp.h"
#include "utils.h"

/* Namespaces */
using namespace std;
using namespace CryptoPP;

// Print the hexadecimal representation of the input string.
void printStringInHex(const std::string& str) {
  std::cout << "s: Premaster secret : ";
  for (size_t i = 0; i < str.length(); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(static_cast<unsigned char>(str[i]));
  }
  std::cout << std::endl;
}

//Compare received server certificate with the expected server certificate for validation.
bool validate_cert(string rx_client_cert, string rx_client_pk,
                   string client_cert) {
  return (rx_client_cert == client_cert);
}

AutoSeededRandomPool rng;

SslServer::SslServer() {
  string datetime;
  if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0) exit(1);

  this->logger_ = new Logger(("ssl_server_" + datetime + ".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Server Log at " + datetime);

  this->closed_ = false;

  generate_pqg(this->dh_p_, this->dh_q_, this->dh_g_);       // init dhe
  generate_rsa_keys(this->private_key_, this->public_key_);  // init rsa
}

SslServer::~SslServer() {
  if (!this->closed_) this->shutdown();
  delete this->logger_;
}

int SslServer::start(int num_clients) {
  if (this->closed_) return -1;
  return this->tcp_->socket_listen(num_clients);
}

SSL* SslServer::accept() {
  if (this->closed_) return NULL;

  TCP* cxn = this->tcp_->socket_accept();
  if (cxn == NULL) {
    cerr << "error when accepting" << endl;
    return NULL;
  }

  cxn->set_logger(this->logger_);

  SSL* ssl_cxn = new SSL(cxn);
  this->clients_.push_back(ssl_cxn);

  // Hardcoded certificate values simulate SSL handshake due to absence of third-party validation.
  string server_cert =
      "db6dd87c3f12312872c3b2b653becb281cf2f4c22e256b95b2dcaffed19562f3";
  string client_cert =
      "cd5a1c33684c1a691ee97f1014a35db2858d5632a4fccb74711bb883425f549f";

  //============================ CLIENT_HELLO_RECV ============================//
  Record rx_recordch;
  ssl_cxn->recv(&rx_recordch);

  string temp_buffer = rx_recordch.data;
  temp_buffer = temp_buffer.substr(0, rx_recordch.hdr.length);

  int msg_type = stoi(temp_buffer.substr(0, 2), nullptr, 16);  
  int cipher_type = stoi(temp_buffer.substr(2, 2), nullptr, 16);

  string clientRandBase64Str = rx_recordch.data;
  clientRandBase64Str = clientRandBase64Str.substr(4);

  CryptoPP::Base64Decoder base64Decoder;
  SecByteBlock clientRandDecoded(32);
  base64Decoder.Attach(new CryptoPP::ArraySink(clientRandDecoded, clientRandDecoded.size()));
  base64Decoder.Put(reinterpret_cast<const byte*>(clientRandBase64Str.data()),
                    clientRandBase64Str.size());
  base64Decoder.MessageEnd();
  string clientRandDecodedStr(
      reinterpret_cast<const char*>(clientRandDecoded.data()),
      clientRandDecoded.size());

  if (msg_type == SSL::HS_CLIENT_HELLO && cipher_type == SSL::KE_RSA) {
    cout << "s: SERVER AFFIRMATIVE" << endl;

    //=========================== SENDING_SERVER_HELLO ===============================//

    //Serialize message type to hexadecimal string for hello handshake.
    uint8_t hex_input = SSL::HS_SERVER_HELLO;
    stringstream stream;
    stream << hex << setw(2) << setfill('0') << static_cast<int>(hex_input);
    string hex_string1 = stream.str();

    //Serialize key exchange type and generate server random data block.
    uint8_t hex_input1 = SSL::KE_RSA;
    stringstream stream1;
    stream1 << hex << setw(2) << setfill('0') << static_cast<int>(hex_input1);
    string hex_string2 = stream1.str();

    // Generating server Random
    SecByteBlock serverRandBlock(32);
    rng.GenerateBlock(serverRandBlock.data(), serverRandBlock.size());
    string serverRandStr(
        reinterpret_cast<const char*>(serverRandBlock.data()),
        serverRandBlock.size());

    // Encode server random data block to Base64 format.
    Base64Encoder encoder;
    encoder.Put(serverRandBlock.data(), serverRandBlock.size());
    encoder.MessageEnd();

    string serverRandBase64;
    size_t encodedSize = encoder.MaxRetrievable();
    if (encodedSize) {
      serverRandBase64.resize(encodedSize);
      encoder.Get(reinterpret_cast<byte*>(&serverRandBase64[0]),
                  serverRandBase64.size());
    }

    //Construct and send handshake packet with type, version, and server random data.
    Record tx_record1;
    tx_record1.hdr.type = REC_HANDSHAKE;
    tx_record1.hdr.version = VER_99;
    string body1 = hex_string1 + hex_string2 + serverRandBase64;
    char* data1 = (char*)malloc(body1.length() * sizeof(char));
    memcpy(data1, body1.c_str(), body1.length());
    tx_record1.data = data1;
    tx_record1.hdr.length = body1.length();
    ssl_cxn->send(tx_record1);
    free(data1);

    //===================SENDING_SERVER_PK========================//

    string derPublicKey;
    StringSink sink(derPublicKey);
    this->public_key_.DEREncodePublicKey(sink);

    // Decode the DER-encoded public key
    RSA::PublicKey decodedPublicKey;
    StringSource source(derPublicKey, true /* pump all */);
    decodedPublicKey.BERDecodePublicKey(source, true /* parametersPresent */,
                                        derPublicKey.size());

    // DER-encode the decoded public key and encode it in base64 format
    string derDecodedPublicKey;
    StringSink derSink(derDecodedPublicKey);
    decodedPublicKey.DEREncodePublicKey(derSink);

    string base64DecodedPublicKey;
    StringSource(
        derDecodedPublicKey, true,
        new Base64Encoder(new StringSink(base64DecodedPublicKey), false));

    uint8_t hex_inputc2 = SSL::HS_SERVER_KEY_EXCHANGE;
    stringstream streamc12;
    streamc12 << hex << setw(2) << setfill('0')
              << static_cast<int>(hex_inputc2);
    string hex_stringc22 = streamc12.str();

    Record tx_recordrpk;
    tx_recordrpk.hdr.type = REC_HANDSHAKE;
    tx_recordrpk.hdr.version = VER_99;
    string bodyrpk = hex_stringc22 + base64DecodedPublicKey;
    char* datarpk = (char*)malloc(bodyrpk.length() * sizeof(char));
    memcpy(datarpk, bodyrpk.c_str(), bodyrpk.length());
    tx_recordrpk.data = datarpk;
    tx_recordrpk.hdr.length = bodyrpk.length();
    ssl_cxn->send(tx_recordrpk);
    free(datarpk);

    //===================SENDING_SERVER_CERT========================//

    uint8_t hex_inputcertrsa = SSL::HS_CERTIFICATE;
    stringstream streamccertrsa;
    streamccertrsa << hex << setw(2) << setfill('0')
                   << static_cast<int>(hex_inputcertrsa);
    string hex_stringcertrsa = streamccertrsa.str();

    Record tx_recordrcert;
    tx_recordrcert.hdr.type = REC_HANDSHAKE;
    tx_recordrcert.hdr.version = VER_99;
    string bodyrcert = hex_stringcertrsa + server_cert;
    char* datarcert = (char*)malloc(bodyrcert.length() * sizeof(char));
    memcpy(datarcert, bodyrcert.c_str(), bodyrcert.length());
    tx_recordrcert.data = datarcert;
    tx_recordrcert.hdr.length = bodyrcert.length();
    ssl_cxn->send(tx_recordrcert);
    free(datarcert);

    //===================SENDING_SERVER_HELLO_DONE========================//

    // hexadecimal to string (cipher tpe)
    uint8_t hex_inputsh = SSL::HS_SERVER_HELLO_DONE;
    stringstream streamsh;
    streamsh << hex << setw(2) << setfill('0') << static_cast<int>(hex_inputsh);
    string hex_stringsh = streamsh.str();

    Record tx_recordsh;
    tx_recordsh.hdr.type = REC_HANDSHAKE;
    tx_recordsh.hdr.version = VER_99;
    char* datash = (char*)malloc(hex_stringsh.length() * sizeof(char));
    memcpy(datash, hex_stringsh.c_str(), hex_stringsh.length());
    tx_recordsh.data = datash;
    tx_recordsh.hdr.length = hex_stringsh.length();
    ssl_cxn->send(tx_recordsh);
    free(datash);

    //=====================RECV_PREMASTER_KEY==================//
    Record rx_record1;
    ssl_cxn->recv(&rx_record1);

    temp_buffer = rx_record1.data;
    temp_buffer =
        temp_buffer.substr(0, rx_record1.hdr.length);
    string receivedBase64EncodedCiphertext = temp_buffer.substr(2);

    string receivedCiphertext;
    StringSource ss(receivedBase64EncodedCiphertext, true,
                    new Base64Decoder(new StringSink(receivedCiphertext)));

    string plain_text;

    // Decrypt the cipher text using the private key
    rsa_decrypt(this->private_key_, &plain_text, receivedCiphertext);

    // Print the premaster key to the console
    printStringInHex(plain_text);

    SecByteBlock recoveredPremaster(
        reinterpret_cast<const byte*>(plain_text.data()), plain_text.size());

    SecByteBlock derivedKey;
    derivedKey.resize(16);
    size_t keySize = 16;
    SecByteBlock serverKey1(keySize);

    // derive_key
    SecByteBlock seed(serverRandBlock.size() + clientRandDecoded.size());
    memcpy(seed.data(), serverRandBlock.data(), serverRandBlock.size());
    memcpy(seed.data() + serverRandBlock.size(), clientRandDecoded.data(),
           clientRandDecoded.size());

    // Derive the key using HKDF with HMAC-SHA256
    HKDF<SHA256>().DeriveKey(
        serverKey1.data(), serverKey1.size(), recoveredPremaster.data(),
        recoveredPremaster.size(), seed.data(), seed.size(),
        reinterpret_cast<const byte*>("key expansion"),
        strlen("key expansion"));

    string serverKeyStr1(reinterpret_cast<const char*>(serverKey1.data()),
                         serverKey1.size());

    ssl_cxn->set_shared_key(serverKey1.data(), serverKey1.size());
  }

  if (msg_type == SSL::HS_CLIENT_HELLO && cipher_type == SSL::KE_DHE) {

    //==========================GENERATING_P_G_Q=======================//

    AutoSeededRandomPool rng;
    Integer dh_p, dh_q, dh_g;

    DH dh;
    dh.AccessGroupParameters().GenerateRandomWithKeySize(rng, 1024);

    dh_p = dh.GetGroupParameters().GetModulus();
    dh_q = dh.GetGroupParameters().GetSubgroupOrder();
    dh_g = dh.GetGroupParameters().GetGenerator();

    DH serverDH;

    serverDH.AccessGroupParameters().Initialize(dh_p, dh_q, dh_g);

    stringstream sspqg;
    sspqg << hex << dh_p;
    string p_str = sspqg.str();
    sspqg.str("");
    sspqg << hex << dh_q;
    string q_str = sspqg.str();
    sspqg.str("");
    sspqg << hex << dh_g;
    string g_str = sspqg.str();

//========================== SERVER HELLO =======================//

    // hexadecimal to string (server hello)
    uint8_t hex_inputdh = SSL::HS_SERVER_HELLO;
    stringstream streamdh;
    streamdh << hex << setw(2) << setfill('0') << static_cast<int>(hex_inputdh);
    string hex_stringdh = streamdh.str();

    // hexadecimal to string (cipher tpe)
    uint8_t hex_inputdh1 = SSL::KE_DHE;
    stringstream streamdh1;
    streamdh1 << hex << setw(2) << setfill('0') << static_cast<int>(hex_inputdh1);
    string hex_stringdh1 = streamdh1.str();

    // generating server random
    SecByteBlock serverRandBlock1(32);
    rng.GenerateBlock(serverRandBlock1.data(), serverRandBlock1.size());
    string serverRandStr1(
        reinterpret_cast<const char*>(serverRandBlock1.data()),
        serverRandBlock1.size());

    // encode the server random in base64 format
    Base64Encoder encoder;
    encoder.Put(serverRandBlock1.data(), serverRandBlock1.size());
    encoder.MessageEnd();

    string serverRandBase64;
    size_t encodedSize = encoder.MaxRetrievable();
    if (encodedSize) {
      serverRandBase64.resize(encodedSize);
      encoder.Get(reinterpret_cast<byte*>(&serverRandBase64[0]),
                  serverRandBase64.size());
    }
    Record tx_recorddh;
    tx_recorddh.hdr.type = REC_HANDSHAKE;
    tx_recorddh.hdr.version = VER_99;
    string bodydh = hex_stringdh + hex_stringdh1 + serverRandBase64 + p_str + q_str + g_str;
    char* datadh = (char*)malloc(bodydh.length() * sizeof(char));
    memcpy(datadh, bodydh.c_str(), bodydh.length());
    tx_recorddh.data = datadh;
    tx_recorddh.hdr.length = bodydh.length();
    ssl_cxn->send(tx_recorddh);
    free(datadh);

    // Generate server's private and public keys
    SecByteBlock privateKey(serverDH.PrivateKeyLength());
    SecByteBlock publicKey(serverDH.PublicKeyLength());
    serverDH.GenerateKeyPair(rng, privateKey, publicKey);

    //======================SENDING_PK TO CLIENT=================================//

    SecByteBlock public_key = publicKey;  // the public key as a SecByteBlock

    // Encode the public key as a base64 string
    string public_key_str;
    StringSink sink(public_key_str);
    ArraySource(public_key.data(), public_key.size(), true,
                new Base64Encoder(new Redirector(sink),
                                  false /* do not insert line breaks */));

   //======================SENDING_PK TO CLIENT=================================//

    uint8_t hex_inputc2 = SSL::HS_SERVER_KEY_EXCHANGE;
    stringstream streamc12;
    streamc12 << hex << setw(2) << setfill('0')
              << static_cast<int>(hex_inputc2);
    string hex_stringc22 = streamc12.str();

    Record tx_recorddhpk;
    tx_recorddhpk.hdr.type = REC_HANDSHAKE;
    tx_recorddhpk.hdr.version = VER_99;
    string bodydhpk = hex_stringc22 + public_key_str;
    char* datadhpk = (char*)malloc(bodydhpk.length() * sizeof(char));
    memcpy(datadhpk, bodydhpk.c_str(), bodydhpk.length());
    tx_recorddhpk.data = datadhpk;
    tx_recorddhpk.hdr.length = bodydhpk.length();
    ssl_cxn->send(tx_recorddhpk);
    free(datadhpk);

    //===================SENDING_SERVER_CERT========================//

    uint8_t hex_inputcertdhe = SSL::HS_CERTIFICATE;
    stringstream streamccertdhe;
    streamccertdhe << hex << setw(2) << setfill('0')
                   << static_cast<int>(hex_inputcertdhe);
    string hex_stringcertdhe = streamccertdhe.str();

    Record tx_recordrcert_dhe;
    tx_recordrcert_dhe.hdr.type = REC_HANDSHAKE;
    tx_recordrcert_dhe.hdr.version = VER_99;
    string bodyrcert = hex_stringcertdhe + server_cert;
    char* datarcert = (char*)malloc(bodyrcert.length() * sizeof(char));
    memcpy(datarcert, bodyrcert.c_str(), bodyrcert.length());
    tx_recordrcert_dhe.data = datarcert;
    tx_recordrcert_dhe.hdr.length = bodyrcert.length();
    ssl_cxn->send(tx_recordrcert_dhe);
    free(datarcert);

    //===================SENDING_SERVER_HELLO_DONE========================//

    // hexadecimal to string (cipher tpe)
    uint8_t hex_inputsh = SSL::HS_SERVER_HELLO_DONE;
    stringstream streamsh;
    streamsh << hex << setw(2) << setfill('0') << static_cast<int>(hex_inputsh);
    string hex_stringsh = streamsh.str();

    Record tx_recordsh;
    tx_recordsh.hdr.type = REC_HANDSHAKE;
    tx_recordsh.hdr.version = VER_99;
    string bodysh = hex_stringsh;
    char* datash = (char*)malloc(bodysh.length() * sizeof(char));
    memcpy(datash, bodysh.c_str(), bodysh.length());
    tx_recordsh.data = datash;
    tx_recordsh.hdr.length = bodysh.length();
    ssl_cxn->send(tx_recordsh);
    free(datash);

    //=========RECEIVE_PK_FROM_CLIENT===============================//
    Record rx_recordpk;
    ssl_cxn->recv(&rx_recordpk);
    temp_buffer = rx_recordpk.data;
    temp_buffer =
        temp_buffer.substr(0, rx_recordpk.hdr.length);

    string clientpubkey = temp_buffer.substr(2);

    string clientPublicKeyStr;
    CryptoPP::StringSink stringSink(clientPublicKeyStr);
    CryptoPP::StringSource(
        (clientpubkey), true,
        new CryptoPP::Base64Decoder(new CryptoPP::Redirector(stringSink)));

    CryptoPP::SecByteBlock clientPublicKey(
        reinterpret_cast<const unsigned char*>(clientPublicKeyStr.data()),
        clientPublicKeyStr.size());


    //================ RECEIVING_CERT_FROM_CLIENT =============//
    Record rx_record_cert_dhe;
    ssl_cxn->recv(&rx_record_cert_dhe);

    // Base64-encoded public key
    string temp_buffer1 = rx_record_cert_dhe.data;

    temp_buffer1 =
        temp_buffer1.substr(0, rx_record_cert_dhe.hdr.length);
    string client_cert_dhe = temp_buffer1.substr(2);

    cout << "s: Client Certificate : " << client_cert_dhe << endl;

    if (validate_cert(client_cert_dhe, clientPublicKeyStr, client_cert))
      cout << "s: Client certificate validation successful" << endl;
    else
      cout << "s: Client certificate validation failed" << endl;


    // //==============GENERATING_MASTER_SECRET==================//

    SecByteBlock preMasterSecret(serverDH.AgreedValueLength());

    // Encode the public key as a base64 string
    string premaster;
    StringSink sink1(premaster);
    ArraySource(preMasterSecret.data(), preMasterSecret.size(), true,
                new Base64Encoder(new Redirector(sink1),
                                  false /* do not insert line breaks */));

    if (!serverDH.Agree(preMasterSecret, privateKey, clientPublicKey)) {
      cerr << "s: Failed to reach the pre-master secret agreement." << endl;
    }

    size_t keySize = 16;  // Desired size of the derived keys in bytes

    SecByteBlock serverKey(keySize);

    // Concatenate server random and client random to form the seed
    SecByteBlock seed(serverRandBlock1.size() + clientRandDecoded.size());
    memcpy(seed.data(), serverRandBlock1.data(), serverRandBlock1.size());
    memcpy(seed.data() + serverRandBlock1.size(), clientRandDecoded.data(),
           clientRandDecoded.size());

    // Derive the key using HKDF with HMAC-SHA256
    HKDF<SHA256>().DeriveKey(serverKey.data(), serverKey.size(),
                             preMasterSecret.data(), preMasterSecret.size(),
                             seed.data(), seed.size(),
                             reinterpret_cast<const byte*>("key expansion"),
                             strlen("key expansion"));

    string serverKeyStr(reinterpret_cast<const char*>(serverKey.data()),
                        serverKey.size());
    ssl_cxn->set_shared_key(serverKey.data(), serverKey.size());

    // Print the shared key to the console
    printStringInHex(serverKeyStr);
  }

  //==================== SERVER RECEIVE HANDSHAKE FINISH ====================//

  Record rx_recordf2;
  ssl_cxn->recv(&rx_recordf2);

  temp_buffer = rx_recordf2.data;
  temp_buffer = temp_buffer.substr(0, rx_recordf2.hdr.length);
  int rx_msg_type = stoi(temp_buffer.substr(0, 2), nullptr, 16);  
  if (rx_msg_type == SSL::HS_FINISHED) cout << "s: handshake completed" << endl;

  return ssl_cxn;
}

int SslServer::shutdown() {
  if (this->closed_) return -1;

  // pop all clients
  while (!this->clients_.empty()) {
    SSL* cxn = this->clients_.back();
    this->clients_.pop_back();
    if (cxn != NULL) delete cxn;
  }
  return 0;
}

vector<SSL*> SslServer::get_clients() const {
  return vector<SSL*>(this->clients_);
}

int SslServer::broadcast(const string& msg) {
  if (this->closed_) return -1;

  int num_sent = 0;

  for (vector<SSL*>::iterator it = this->clients_.begin();
       it != this->clients_.end(); ++it) {
    ssize_t send_len;
    send_len = (*it)->send(msg);
    if (send_len == (unsigned int)msg.length()) num_sent += 1;
  }
  return num_sent;
}