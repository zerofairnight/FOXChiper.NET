namespace FOXCipher.NET
{
    using System;
    using System.Security.Cryptography;

    public class Decrypt2Transform : ICryptoTransform
    {
        private readonly uint _key;

        // internal rotating key
        private uint _blockKey;

        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        public bool CanReuseTransform => false; // rotating-based transform

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        public bool CanTransformMultipleBlocks => true;

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        public int InputBlockSize => 64;

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        public int OutputBlockSize => 64;

        /// <summary>
        /// Create a new <see cref="Decrypt2Transform"/> instance.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        public Decrypt2Transform(uint key)
        {
            _key = 278 * key;
            _blockKey = key | ((key ^ 25974) << 16);
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
            UnsafeTransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);

            return inputCount;
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
            UnsafeTransformFinalBlock(inputBuffer, inputOffset, inputCount, outputBuffer);
            return outputBuffer;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        void IDisposable.Dispose() { }

        // TODO: reconsider using unsafe
        private unsafe void UnsafeTransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            int size = inputCount;

            fixed (byte* pDestBase = outputBuffer, pSrcBase = inputBuffer)
            {
                // offset the pointers
                uint* pDest = (uint*)pDestBase + outputOffset;
                uint* pSrc = (uint*)pSrcBase + inputOffset;

                for (; size >= 64; size -= 64)
                {
                    uint j = 16;
                    do
                    {
                        *pDest = _blockKey ^ *pSrc;
                        _blockKey = _key + 48828125 * _blockKey;

                        --j;
                        pDest++;
                        pSrc++;
                    } while (j > 0);
                }
            }
        }

        private unsafe void UnsafeTransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer)
        {
            int size = inputCount;

            fixed (byte* pDestBase = outputBuffer, pSrcBase = inputBuffer)
            {
                // offset the pointers
                uint* pDest = (uint*)pDestBase;
                uint* pSrc = (uint*)pSrcBase + inputOffset;

                for (; size >= 16; pSrc += 4)
                {
                    *pDest = _blockKey ^ *pSrc;
                    uint v7 = _key + 48828125 * _blockKey;
                    *(pDest + 1) = v7 ^ *(pSrc + 1);
                    uint v8 = _key + 48828125 * v7;
                    *(pDest + 2) = v8 ^ *(pSrc + 2);
                    uint v9 = _key + 48828125 * v8;
                    *(pDest + 3) = v9 ^ *(pSrc + 3);

                    _blockKey = _key + 48828125 * v9;
                    size -= 16;
                    pDest += 4;
                }

                for (; size >= 4; pSrc++)
                {
                    *pDest = _blockKey ^ *pSrc;

                    _blockKey = _key + 48828125 * _blockKey;
                    size -= 4;
                    pDest++;
                }
            }
        }
    }
}
