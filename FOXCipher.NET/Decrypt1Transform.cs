namespace FOXCipher.NET
{
    using System;
    using System.Security.Cryptography;

    public class Decrypt1Transform : ICryptoTransform
    {
        private static readonly uint[] decryptionTable =
        {
            0xBB8ADEDB,
            0x65229958,
            0x08453206,
            0x88121302,
            0x4C344955,
            0x2C02F10C,
            0x4887F823,
            0xF3818583
        };

        private readonly int _version;
        private readonly uint _hashLow;
        private readonly ulong _seed;
        private readonly uint _seedLow;
        private readonly uint _seedHigh;

        // internal counter
        private int _position;

        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        public bool CanReuseTransform => false; // position-based transform

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        public bool CanTransformMultipleBlocks => true;

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        public int InputBlockSize => 8; // sizeof(ulong)

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        public int OutputBlockSize => 8;

        /// <summary>
        /// Create a new <see cref="Decrypt1Transform"/> instance.
        /// </summary>
        /// <param name="version">The algorithm version, 1 or 2.</param>
        /// <param name="hash">The encryption hash.</param>
        /// <param name="seed">The encryption seed.</param>
        public Decrypt1Transform(int version, ulong hash, ulong seed)
        {
            _version = version;

            _hashLow = (uint)(hash & 0xFFFFFFFF);

            _seed = seed;
            _seedLow = (uint)(seed & 0xFFFFFFFF);
            _seedHigh = (uint)(seed >> 32);
        }

        /// <summary>
        /// Transforms the specified region of the input byte array and copies the resulting transform to the specified region of the output byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
        /// <param name="outputBuffer">The output to which to write the transform.</param>
        /// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
        /// <returns>The number of bytes written.</returns>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            int blocks = inputCount / InputBlockSize;

            for (int i = 0; i < blocks; i++)
            {
                int offset1 = i * 8; // sizeof(ulong)
                int offset2 = offset1 + 4; // sizeof(uint)

                // read 8 bytes
                uint u1 = BitConverter.ToUInt32(inputBuffer, inputOffset + offset1);
                uint u2 = BitConverter.ToUInt32(inputBuffer, inputOffset + offset2);

                int offset1Absolute = offset1 + _position;
                int index = (int)(2 * ((_hashLow + offset1Absolute / 11) % 4));

                // version 1
                if (_version != 2)
                {
                    u1 ^= decryptionTable[index];
                    u2 ^= decryptionTable[index + 1];
                }
                // version 2
                else
                {
                    u1 ^= decryptionTable[index] ^ _seedLow;
                    u2 ^= decryptionTable[index + 1] ^ _seedHigh;
                }

                Buffer.BlockCopy(BitConverter.GetBytes(u1), 0, outputBuffer, outputOffset + offset1, sizeof(uint));
                Buffer.BlockCopy(BitConverter.GetBytes(u2), 0, outputBuffer, outputOffset + offset2, sizeof(uint));
            }

            // increment the position
            _position += 8 * blocks;

            // we have read n block each of size InputBlockSize
            return blocks * InputBlockSize; // this is inputCount
        }

        /// <summary>
        /// Transforms the specified region of the specified byte array.
        /// </summary>
        /// <param name="inputBuffer">The input for which to compute the transform.</param>
        /// <param name="inputOffset">The offset into the byte array from which to begin using data.</param>
        /// <param name="inputCount">The number of bytes in the byte array to use as data.</param>
        /// <returns>The computed transform.</returns>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] outputBuffer = new byte[inputCount];

            if (_version != 2)
            {
                for (int i = 0; i < inputCount; i++)
                {
                    int offsetAbsolute = i + _position;

                    int index = (int)(2 * ((_hashLow + (offsetAbsolute - (offsetAbsolute % sizeof(long))) / 11) % 4));
                    int decryptionIndex = i % sizeof(long);

                    uint xorMask = decryptionIndex < 4 ? decryptionTable[index] : decryptionTable[index + 1];
                    byte xorMaskByte = (byte)((xorMask >> (8 * decryptionIndex)) & 0xff);

                    byte b1 = (byte)(inputBuffer[i] ^ xorMaskByte);

                    outputBuffer[i] = b1;
                }
            }
            else
            {
                for (int i = 0; i < inputCount; i++)
                {
                    int offsetBlock = i - (i % sizeof(long));
                    int offsetBlockAbolute = offsetBlock + _position;

                    int index = 2 * (int)((_hashLow + _seed + (ulong)(offsetBlockAbolute / 11)) % 4);
                    int decryptionIndex = i % sizeof(long);

                    uint xorMask = decryptionIndex < 4 ? decryptionTable[index] : decryptionTable[index + 1];
                    byte xorMaskByte = (byte)((xorMask >> (8 * (decryptionIndex % 4))) & 0xff);

                    uint seedMask = decryptionIndex < 4 ? _seedLow : _seedHigh;
                    byte seedByte = (byte)((seedMask >> (8 * (decryptionIndex % 4))) & 0xff);

                    byte b1 = (byte)(inputBuffer[i] ^ (byte)(xorMaskByte ^ seedByte));

                    outputBuffer[i] = b1;
                }
            }

            // increment the position
            _position += inputCount;

            return outputBuffer;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        void IDisposable.Dispose() { }
    }
}
