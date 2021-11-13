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
    internal static class Utilities
    {
        internal static void Copy(byte[] source, ref byte[] destination, int length)
        {
            for (int i = 0; i < length; i++)
            {
                destination[i] = source[i];
            }
        }

        internal static void Increment(ref byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                counter[i]++;
                if (counter[i] != 0) { break; }
            }
        }

        internal static unsafe byte[] Xor(byte[] message, byte[] keystream)
        {
            int chunks = message.Length / 8;
            fixed (byte* messagePointer = message)
            fixed (byte* keystreamPointer = keystream)
            {
                long* m = (long*)messagePointer;
                long* k = (long*)keystreamPointer;
                for (int i = 0; i < chunks; i++)
                {
                    *m ^= *k;
                    m++;
                    k++;
                }
            }
            for (int i = chunks * 8; i < message.Length; i++)
            {
                message[i] ^= keystream[i];
            }
            return message;
        }
    }
}
