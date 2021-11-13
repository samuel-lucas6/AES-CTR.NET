using System.Text;
using Sodium;
using AesCTRDotNet;

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

namespace AesCTRTest
{
    class Program
    {
        private const string _success = "Pass";
        private const string _fail = "Fail";

        static void Main(string[] _)
        {
            // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf - CTR EXAMPLE VECTORS F.5.5 CTR-AES256.Encrypt (pg. 57)
            byte[] key = Utilities.HexToBinary("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
            byte[] counter = Utilities.HexToBinary("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            Console.WriteLine("128-bit nonce");
            Console.WriteLine("-------------");
            // All NIST tests combined
            TestCase1(key, counter);
            // Block #1
            TestCase2(key, counter);
            // Block #2
            Increment(ref counter);
            TestCase3(key, counter);
            // Block #3
            Increment(ref counter);
            TestCase4(key, counter);
            // Block #4
            Increment(ref counter);
            TestCase5(key, counter);
            // Custom test using a 17 byte message, meaning the blockCount should round up
            Increment(ref counter);
            TestCase6(key, counter);
            Console.WriteLine();
            Console.WriteLine("64-bit nonce");
            Console.WriteLine("------------");
            // 64-bit nonce
            TestCase6(key, SodiumCore.GetRandomBytes(8));
            Console.WriteLine();
            Console.WriteLine("96-bit nonce");
            Console.WriteLine("------------");
            // 96-bit nonce
            TestCase6(key, SodiumCore.GetRandomBytes(12));
            Console.ReadLine();
        }

        private static void Increment(ref byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                counter[i]++;
                if (counter[i] != 0) { break; }
            }
        }

        private static void TestCase1(byte[] key, byte[] nonce)
        {
            byte[] expectedPlaintext = Utilities.HexToBinary("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
            byte[] expectedCiphertext = Utilities.HexToBinary("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6");
            byte[] actualCiphertext = AesCTR.Encrypt(expectedPlaintext, nonce, key);
            Console.WriteLine($"Test 1.1: {(Utilities.Compare(expectedCiphertext, actualCiphertext) ? _success : _fail)}");
            byte[] actualPlaintext = AesCTR.Decrypt(actualCiphertext, nonce, key);
            Console.WriteLine($"Test 1.2: {(Utilities.Compare(expectedPlaintext, actualPlaintext) ? _success : _fail)}");
        }

        private static void TestCase2(byte[] key, byte[] nonce)
        {
            byte[] expectedPlaintext = Utilities.HexToBinary("6bc1bee22e409f96e93d7e117393172a");
            byte[] expectedCiphertext = Utilities.HexToBinary("601ec313775789a5b7a7f504bbf3d228");
            byte[] actualCiphertext = AesCTR.Encrypt(expectedPlaintext, nonce, key);
            Console.WriteLine($"Test 2.1: {(Utilities.Compare(expectedCiphertext, actualCiphertext) ? _success : _fail)}");
            byte[] actualPlaintext = AesCTR.Decrypt(actualCiphertext, nonce, key);
            Console.WriteLine($"Test 2.2: {(Utilities.Compare(expectedPlaintext, actualPlaintext) ? _success : _fail)}");
        }

        private static void TestCase3(byte[] key, byte[] nonce)
        {
            byte[] expectedPlaintext = Utilities.HexToBinary("ae2d8a571e03ac9c9eb76fac45af8e51");
            byte[] expectedCiphertext = Utilities.HexToBinary("f443e3ca4d62b59aca84e990cacaf5c5");
            byte[] actualCiphertext = AesCTR.Encrypt(expectedPlaintext, nonce, key);
            Console.WriteLine($"Test 3.1: {(Utilities.Compare(expectedCiphertext, actualCiphertext) ? _success : _fail)}");
            byte[] actualPlaintext = AesCTR.Decrypt(actualCiphertext, nonce, key);
            Console.WriteLine($"Test 3.2: {(Utilities.Compare(expectedPlaintext, actualPlaintext) ? _success : _fail)}");
        }

        private static void TestCase4(byte[] key, byte[] nonce)
        {
            byte[] expectedPlaintext = Utilities.HexToBinary("30c81c46a35ce411e5fbc1191a0a52ef");
            byte[] expectedCiphertext = Utilities.HexToBinary("2b0930daa23de94ce87017ba2d84988d");
            byte[] actualCiphertext = AesCTR.Encrypt(expectedPlaintext, nonce, key);
            Console.WriteLine($"Test 4.1: {(Utilities.Compare(expectedCiphertext, actualCiphertext) ? _success : _fail)}");
            byte[] actualPlaintext = AesCTR.Decrypt(actualCiphertext, nonce, key);
            Console.WriteLine($"Test 4.2: {(Utilities.Compare(expectedPlaintext, actualPlaintext) ? _success : _fail)}");
        }

        private static void TestCase5(byte[] key, byte[] nonce)
        {
            byte[] expectedPlaintext = Utilities.HexToBinary("f69f2445df4f9b17ad2b417be66c3710");
            byte[] expectedCiphertext = Utilities.HexToBinary("dfc9c58db67aada613c2dd08457941a6");
            byte[] actualCiphertext = AesCTR.Encrypt(expectedPlaintext, nonce, key);
            Console.WriteLine($"Test 5.1: {(Utilities.Compare(expectedCiphertext, actualCiphertext) ? _success : _fail)}");
            byte[] actualPlaintext = AesCTR.Decrypt(actualCiphertext, nonce, key);
            Console.WriteLine($"Test 5.2: {(Utilities.Compare(expectedPlaintext, actualPlaintext) ? _success : _fail)}");
        }

        private static void TestCase6(byte[] key, byte[] nonce)
        {
            byte[] expectedPlaintext = Encoding.UTF8.GetBytes("This is a test...");
            var plaintext = new byte[expectedPlaintext.Length];
            expectedPlaintext.CopyTo(plaintext, index: 0);
            byte[] ciphertext = AesCTR.Encrypt(plaintext, nonce, key);
            bool error = false;
            for (int i = 0; i < ciphertext.Length; i++)
            {
                if (ciphertext[i] == expectedPlaintext[i]) { error = true; break; }
            }
            Console.WriteLine($"Test 6.1: {(error ? _fail : _success)}");
            byte[] actualPlaintext = AesCTR.Decrypt(ciphertext, nonce, key);
            Console.WriteLine($"Test 6.2: {(Utilities.Compare(expectedPlaintext, actualPlaintext) ? _success : _fail)}");
        }
    }
}