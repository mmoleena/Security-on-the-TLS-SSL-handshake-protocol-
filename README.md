# Security on the TLS/SSL Handshake Protocol and Application Data Protocol

The project illustrates the TLS/SSL handshake key agreement in C++ using both RSA and DHE methods.

## Why is a Handshake Necessary?

### Meeting a Trusted Contact
The handshake verifies identities using digital certificates, preventing imposters.

### Secret Code Exchange
Complex cryptographic algorithms like RSA or DHE establish a shared secret key for encryption.

### Building a Secure Tunnel
An encrypted connection is established, accessible only to authorized parties.

## Advantages of the Handshake

- **Confidentiality:** Encrypting data secures it from eavesdroppers.
- **Integrity:** MACs ensure data remains unaltered.
- **Authentication (Optional):** Digital certificates prevent impersonation.

## Project Structure

The project directory is organized as follows:

- `/src`
  - `/tcp`: TCP implementation
  - `/ssl`: SSL implementation
  - `/cryptopp`: Crypto primitives
- `/tst`
  - `/ssl`: Test Bench (Application Layer)

All makefiles are provided.

## Functions

Applications communicate using the following SSL functions:

- **`SSL::send(string)`**: Encrypts the string and sends it.
- **`SSL::recv(string&)`**: Receives an encrypted string and then decrypts it.
