using System;
using System.Security.Cryptography;

/*
    AES-CTR.NET: A .NET implementation of AES-CTR.
    Copyright (c) 2021 Samuel Lucas

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace AesCTRDotNet
{
    public static class AesCTR
    {
        public const int KeySize = 32;
        public const int NonceSize = 8;
        public const int BlockSize = 16;

        public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key)
        {
            if (message == null || message.Length == 0) { throw new ArgumentOutOfRangeException(nameof(message), "The message/ciphertext cannot be null or empty."); }
            if (nonce == null || (nonce.Length != NonceSize & nonce.Length != 12 & nonce.Length != 16)) { throw new ArgumentOutOfRangeException(nameof(nonce), $"The nonce must be {NonceSize}, 12, or 16 bytes."); }
            if (key == null || key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), $"The key must be {KeySize} bytes."); }
            using (var aes = new AesCryptoServiceProvider() { Mode = CipherMode.ECB, Padding = PaddingMode.None })
            {
                var counter = new byte[BlockSize];
                Utilities.Copy(nonce, ref counter, nonce.Length);
                using (var encryptor = aes.CreateEncryptor(key, iv: new byte[counter.Length]))
                {
                    int blockCount = (message.Length + counter.Length - 1) / counter.Length;
                    var keystream = new byte[counter.Length * blockCount];
                    int outputOffset = 0;
                    for (int i = 0; i < blockCount; i++)
                    {
                        encryptor.TransformBlock(counter, inputOffset: 0, counter.Length, keystream, outputOffset);
                        Utilities.Increment(ref counter);
                        outputOffset += counter.Length;
                    }
                    return Utilities.Xor(message, keystream);
                }
            }
        }

        public static byte[] Decrypt(byte[] ciphertext, byte[] nonce, byte[] key)
        {
            return Encrypt(ciphertext, nonce, key);
        }

        public static void IncrementNonce(ref byte[] nonce)
        {
            for (int i = 0; i < nonce.Length; i++)
            {
                nonce[i]++;
                if (nonce[i] != 0) { break; }
            }
        }
    }
}
