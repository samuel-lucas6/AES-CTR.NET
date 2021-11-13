[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/AES-CTR.NET/blob/main/LICENSE)
[![CodeQL](https://github.com/samuel-lucas6/AES-CTR.NET/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/samuel-lucas6/AES-CTR.NET/actions)

# AES-CTR.NET
A .NET implementation of [AES-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) because it is not available in the [System.Security.Cryptography](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.ciphermode?view=net-6.0) namespace.

## Usage
### ⚠️Warnings
1. **NEVER** reuse a nonce with the same key.
2. AES-CTR is **NOT** an authenticated encryption mode. You **MUST** apply a MAC to the ciphertext, as explained [here](https://github.com/samuel-lucas6/Cryptography-Guidelines#message-authentication-codes).
3. This library does **NOT** support secret nonces because the increment function does **NOT** run in constant time.

### Nonces
This library supports three nonce sizes for interoperability reasons:
1. A 64-bit counter nonce, allowing the encryption of 2^64 bytes for a single (key, nonce) pair and per key.
2. A 96-bit counter nonce, allowing the encryption of 256 GB for a single (key, nonce) pair and 2^64 bytes per key.
3. A 128-bit random nonce, allowing the encryption of 2^64 bytes for a single (key, nonce) pair and [who knows](https://crypto.stackexchange.com/a/86710) exactly how much per key but likely a lot less than 2^64 bytes.

Periodic rekeying (e.g. for each message) is strongly recommended to avoid these limitations. I recommend a 64-bit counter nonce, especially if you do not intend to regularly rekey.

### Example
Here is a code example using a random key and a 64-bit counter nonce:

```c#
// The message could be a file
byte[] message = Encoding.UTF8.GetBytes("Hello world!");

// A 64-bit or 96-bit nonce should start as an empty byte array of 0s. A 128-bit nonce should be random
var nonce = new byte[AesCTR.NonceSize];

// The key can be randomly generated or derived using a KDF (e.g. Argon2, HKDF, etc)
var key = new byte[AesCTR.KeySize];
RandomNumberGenerator.Create().GetBytes(key);

// Encrypt the message. The message parameter will be overwritten with the ciphertext
byte[] ciphertext = AesCTR.Encrypt(message, nonce, key);

// Decrypt the ciphertext. The ciphertext parameter will be overwritten with the plaintext
byte[] plaintext = AesCTR.Decrypt(ciphertext, nonce, key);

// Here is another message
byte[] message2 = Encoding.UTF8.GetBytes("Goodbye cruel world...");

// Increment a 64-bit or 96-bit nonce to encrypt again using the same key. A 128-bit nonce should be random
AesCTR.IncrementNonce(ref nonce);
byte[] ciphertext2 = AesCTR.Encrypt(message2, nonce, key);
```

## Design
1. Only 256-bit keys are supported because 128-bit keys can allow for [batch attacks](https://blog.cr.yp.to/20151120-batchattacks.html) and are not considered [post-quantum secure](https://media.defense.gov/2021/Aug/04/2002821837/-1/-1/1/Quantum_FAQs_20210804.PDF).
2. A 64-bit counter nonce is recommended because that allows for a 64-bit internal counter whilst discouraging unsafe random nonces.
3. Like in the [Go](https://golang.org/src/crypto/cipher/ctr.go) implementation, the nonce is not incremented in constant time for performance reasons and because the nonce is assumed to be public information.
4. The message parameter is overwritten with the ciphertext for performance reasons. Similarly, the ciphertext parameter is overwritten with the plaintext because the ``Decrypt()`` function just calls the ``Encrypt()`` function.
5. An ``IncrementNonce()`` function is included for ease of use and in an attempt to prevent someone incrementing a 128-bit nonce in big-endian format, which would result in catastrophic nonce reuse. Note that this function does not run in constant time because the internal increment function is not in constant time, as explained in point 3 above.
