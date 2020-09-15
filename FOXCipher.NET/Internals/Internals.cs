namespace FOXCipher.NET
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.IO.Compression;
    using System.Collections.ObjectModel;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    internal class DisposeSafeStream : Stream
    {
        private readonly Stream stream;

        public DisposeSafeStream(Stream stream)
        {
            this.stream = stream;
        }

        public override bool CanRead => stream.CanRead;

        public override bool CanSeek => stream.CanSeek;

        public override bool CanWrite => stream.CanWrite;

        public override long Length => stream.Length;

        public override long Position { get => stream.Position; set => stream.Position = value; }

        public override void Flush() { stream.Flush(); }

        public override int Read(byte[] buffer, int offset, int count) { return stream.Read(buffer, offset, count); }

        public override long Seek(long offset, SeekOrigin origin) { return stream.Seek(offset, origin); }

        public override void SetLength(long value) { stream.SetLength(value); }

        public override void Write(byte[] buffer, int offset, int count) { stream.Write(buffer, offset, count); }
    }

    internal class StreamPositionPreservedWrapper : IDisposable
    {
        Stream stream;
        long pos;

        public StreamPositionPreservedWrapper(Stream stream)
        {
            this.stream = stream;
            this.pos = stream.Position;
        }

        public void Dispose()
        {
            // restore the original position
            stream.Position = pos;
        }
    }

    //
    internal class SectionDataReader // QarArchiveEntrySectionReader
    {
        public const uint RotatingXOR = 0xA2C18EC3;

        private uint xor = RotatingXOR;
        private readonly BinaryReader reader;

        public int Version { get; }
        public int Section { get; private set; }

        public SectionDataReader(BinaryReader reader, int version)
        {
            this.reader = reader;
            Version = version;
        }

        public ulong Next()
        {
            // each section is 8 bytes
            uint i1 = reader.ReadUInt32();
            uint i2 = reader.ReadUInt32();

            var r = DecryptSection(i1, i2);

            Section++;

            return r;
        }

        private ulong DecryptSection(uint i1, uint i2)
        {
            uint[] xorTable =
            {
                0x41441043,
                0x11C22050,
                0xD05608C3,
                0x532C7319
            };

            int i = Section;

            if (Version != 2)
            {
                int offset1 = i * sizeof(ulong);
                int offset2 = i * sizeof(ulong) + sizeof(uint);

                int index1 = (i + (offset1 / 5)) % 4;
                int index2 = (i + (offset2 / 5)) % 4;

                i1 ^= xorTable[index1];
                i2 ^= xorTable[index2];

                return (ulong)i2 << 32 | i1;
            }
            else
            {
                int offset1 = i * sizeof(ulong);
                int offset2 = i * sizeof(ulong) + sizeof(uint);

                uint index1 = (uint)((xor + (offset1 / 5)) % 4);
                uint index2 = (uint)((xor + (offset2 / 5)) % 4);

                i1 ^= xorTable[index1];
                i2 ^= xorTable[index2];

                // totate the xor
                RotateXor(i1, i2);

                return (ulong)i2 << 32 | i1;
            }
        }

        void RotateXor(uint i1, uint i2)
        {
            // rotate the xor
            int rotation = (int)(i2 / 256) % 19;
            uint rotated = (i1 >> rotation) | (i1 << (32 - rotation)); // ROR
            xor ^= rotated;
        }
    }

    // 32 bytes
    internal struct QarArchiveHeader
    {
        public const uint Signature = 0x52415153; // SQAR

        private const uint xorMask1 = 0x41441043;
        private const uint xorMask2 = 0x11C22050;
        private const uint xorMask3 = 0xD05608C3;
        private const uint xorMask4 = 0x532C7319;

        public uint Flags;
        public uint FileCount;
        public uint UnknownCount;
        public uint BlockFileEnd;
        public uint OffsetFirstFile;
        public uint Version; // 1 2
        public uint Unknown2; // 0

        public static bool TryRead(BinaryReader reader, out QarArchiveHeader header)
        {
            header = new QarArchiveHeader();

            // invalid magic number
            if (reader.ReadUInt32() != Signature)
                return false;

            header.Flags = reader.ReadUInt32() ^ xorMask1;
            header.FileCount = reader.ReadUInt32() ^ xorMask2;
            header.UnknownCount = reader.ReadUInt32() ^ xorMask3;
            header.BlockFileEnd = reader.ReadUInt32() ^ xorMask4;
            header.OffsetFirstFile = reader.ReadUInt32() ^ xorMask1;
            header.Version = reader.ReadUInt32() ^ xorMask1; // 1 2
            header.Unknown2 = reader.ReadUInt32() ^ xorMask2; // 0

            // unknow version
            if (header.Version != 1 && header.Version != 2)
                return false;

            // unknow Unknown2... what?
            if (header.Unknown2 != 0)
                return false;

            return true;
        }
    }

    // header is 32 bytes
    // we have 8 bytes more for reasons
    internal struct QarArchiveEntryHeader
    {
        public const uint xorMask1 = 0x41441043;
        public const uint xorMask2 = 0x11C22050;
        public const uint xorMask3 = 0xD05608C3;
        public const uint xorMask4 = 0x532C7319;

        public ulong Hash;
        public uint Size1;
        public uint Size2;
        public byte[] DataHash;
        public ulong Seed
        {
            get
            {
                var hashLow = (uint)(Hash & 0xFFFFFFFF);
                return BitConverter.ToUInt64(DataHash, (int)(hashLow % 2) * 8);
            }
        }
        public QarArchiveEntryContentHeader Content;

        public static bool TryRead(BinaryReader reader, int version, out QarArchiveEntryHeader header)
        {
            header = new QarArchiveEntryHeader();

            // hash 8 bytes
            uint hashLow = reader.ReadUInt32() ^ xorMask1;
            uint hashHigh = reader.ReadUInt32() ^ xorMask1;

            header.Hash = (ulong)hashHigh << 32 | hashLow;

            // size 8 bytes (4+4), compressed and not, the order depends on the version
            header.Size1 = reader.ReadUInt32() ^ xorMask2;
            header.Size2 = reader.ReadUInt32() ^ xorMask3;

            // data hash 16 bytes
            uint md51 = reader.ReadUInt32() ^ xorMask4;
            uint md52 = reader.ReadUInt32() ^ xorMask1;
            uint md53 = reader.ReadUInt32() ^ xorMask1;
            uint md54 = reader.ReadUInt32() ^ xorMask2;

            byte[] md5Hash = new byte[16];
            Buffer.BlockCopy(BitConverter.GetBytes(md51), 0, md5Hash, 0, sizeof(uint));
            Buffer.BlockCopy(BitConverter.GetBytes(md52), 0, md5Hash, 4, sizeof(uint));
            Buffer.BlockCopy(BitConverter.GetBytes(md53), 0, md5Hash, 8, sizeof(uint));
            Buffer.BlockCopy(BitConverter.GetBytes(md54), 0, md5Hash, 12, sizeof(uint));

            header.DataHash = md5Hash;

            // some file have a special signature if they are crypted
            // here we attempt to read the file signature
            QarArchiveEntryContentHeader.TryRead(reader, version, header.Hash, header.Seed, out header.Content);

            return true;
        }
    }

    // the entry content header
    // if the header is missing, Signature is zero
    internal struct QarArchiveEntryContentHeader
    {
        public const uint Signature1 = 0xA0F8EFE6;
        public const uint Signature2 = 0xE3F8EFE6;

        public uint Signature;
        public uint Key;
        public uint Size1;
        public uint Size2;

        // Signature1 8 bytes, Signature2 16 bytes, 0 oterhwise
        public int HeaderSize => Signature == Signature1 ? 8 : Signature == Signature2 ? 16 : 0;
        public bool Encrypted => Signature == Signature1 || Signature == Signature2;

        public static bool TryRead(BinaryReader reader, int version, ulong hash, ulong seed, out QarArchiveEntryContentHeader header)
        {
            header = new QarArchiveEntryContentHeader();

            // attemtp to read the file signature
            // read a chunk for processing
            // a chunk is 8 bytes

            byte[] buffer = new byte[8];

            // not enough data
            if (reader.Read(buffer, 0, buffer.Length) != buffer.Length)
                return false;

            var decryptAlgorithm = new Decrypt1Transform(version, hash, seed);

            // decrypt the buffer
            decryptAlgorithm.TransformBlock(buffer, 0, buffer.Length, buffer, 0);

            // get the encryption type and the key
            header.Signature = BitConverter.ToUInt32(buffer, 0);
            header.Key = BitConverter.ToUInt32(buffer, 4);

            // file not encrypted
            // unset the encryption and the key
            if (header.Signature != Signature1 && header.Signature != Signature2)
            {
                header.Signature = 0;
                header.Key = 0;
            }
            else if (header.Signature == Signature2)
            {
                // not enough data
                if (reader.Read(buffer, 0, buffer.Length) != buffer.Length)
                    return false;

                decryptAlgorithm.TransformBlock(buffer, 0, buffer.Length, buffer, 0);

                // additional 8 bytes
                // the size of the file, excluding the header
                header.Size1 = BitConverter.ToUInt32(buffer, 0);
                header.Size2 = BitConverter.ToUInt32(buffer, 4);

                if (header.Size1 != header.Size2)
                {
                    return false;
                }
            }

            return true;
        }
    }

    //

    internal class QarArchiveEntryStreamReader : Stream
    {
        private QarArchiveEntry entry;

        private Stream stream;
        private Stream baseStream;
        private QarArchiveEntryContentHeader qarArchiveEntryContentHeader;

        private long pos;
        private long len;

        public override bool CanRead => baseStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => len;

        public override long Position { get => pos; set => throw new NotSupportedException(); }

        public QarArchiveEntryStreamReader(QarArchiveEntry entry, Stream stream, QarArchiveEntryContentHeader qarArchiveEntryContentHeader)
        {
            this.entry = entry;
            this.stream = stream;
            this.qarArchiveEntryContentHeader = qarArchiveEntryContentHeader;

            pos = 0;
            len = stream.Length;

            Init();
        }

        void Init()
        {
            QarArchiveEntryContentHeader header = qarArchiveEntryContentHeader;

            var decryptAlgorithm = new Decrypt1Transform(entry.Archive.Version, entry.Hash, entry.Seed);

            var headerSize = header.HeaderSize;

            // read the header size
            // this is not part of our stream
            // but serves as starting point for the cryptography
            if (headerSize > 0)
            {
                byte[] buffer = new byte[headerSize];
                stream.Read(buffer, 0, buffer.Length);
                decryptAlgorithm.TransformBlock(buffer, 0, buffer.Length, buffer, 0);

                len -= headerSize;
            }

            //
            baseStream = new CryptoStream(stream, decryptAlgorithm, CryptoStreamMode.Read);

            // file encrypted
            if (header.Encrypted)
            {
                baseStream = new CryptoStream(baseStream, new Decrypt2Transform(header.Key), CryptoStreamMode.Read);
            }

            // file compressed
            if (entry.Compressed)
            {
                baseStream = new GZipStream(stream, CompressionMode.Decompress, false);
            }

            if (entry.Compressed)
            {
                System.Diagnostics.Debug.Assert(header.HeaderSize == 0);
            }

            // if we have messed up
            if (header.Signature == QarArchiveEntryContentHeader.Signature2)
            {
                System.Diagnostics.Debug.Assert(len == header.Size1);
            }
        }


        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (buffer.Length - offset < count)
                throw new ArgumentException("Offset and count were out of bounds.");

            // do not allow reading past the length
            if (pos + count > len)
            {
                count = (int)(len - pos);
            }

            var i = baseStream.Read(buffer, offset, count);

            pos += i;

            return i;
        }
    }

    //

    internal class SectionStream : Stream
    {
        // the stream is preserved on dispose
        private readonly Stream stream;
        private readonly long position;
        private readonly long length;

        /// <summary>
        /// Gets a value indicating whether the current stream supports reading.
        /// </summary>
        public override bool CanRead => stream.CanRead; // this should be always true

        /// <summary>
        /// Gets a value indicating whether the current stream supports writing.
        /// </summary>
        public override bool CanWrite => false;

        /// <summary>
        /// Gets a value indicating whether the current stream supports seeking.
        /// </summary>
        public override bool CanSeek => stream.CanSeek;

        /// <summary>
        /// Gets the length in bytes of the stream.
        /// </summary>
        public override long Length => length;

        /// <summary>
        /// Gets or sets the position within the current stream.
        /// </summary>
        public override long Position { get => stream.Position - position; set => throw new NotSupportedException(); }

        /// <summary>
        /// Create a new <see cref="SectionStream"/> instance.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="position"></param>
        /// <param name="length"></param>
        public SectionStream(Stream stream, long position, long length)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
            this.position = position;
            this.length = length;
        }

        /// <summary>
        /// Reads a sequence of bytes from the current stream and advances the position within the stream by the number of bytes read.
        /// </summary>
        /// <param name="buffer">An array of bytes. When this method returns, the buffer contains the specified byte array with the values between offset and (offset + count - 1) replaced by the bytes read from the current source.</param>
        /// <param name="offset">The zero-based byte offset in buffer at which to begin storing the data read from the current stream.</param>
        /// <param name="count">The maximum number of bytes to be read from the current stream.</param>
        /// <returns>The total number of bytes read into the buffer. This can be less than the number of bytes requested if that many bytes are not currently available, or zero (0) if the end of the stream has been reached.</returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (buffer.Length - offset < count)
                throw new ArgumentException("Offset and count were out of bounds.");
            if (Position < 0) // can happen if someone move the original stream position
                throw new ArgumentException("Position is out of bounds.");

            // do not allow reading past the length
            if (Position + count > length)
            {
                count = (int)(length - Position);
            }

            return stream.Read(buffer, offset, count);
        }

        /// <summary>
        /// Writes a sequence of bytes to the current stream and advances the current position within this stream by the number of bytes written.
        /// </summary>
        /// <param name="buffer">An array of bytes. This method copies count bytes from buffer to the current stream.</param>
        /// <param name="offset">The zero-based byte offset in buffer at which to begin copying bytes to the current stream.</param>
        /// <param name="count">The number of bytes to be written to the current stream.</param>
        /// <exception cref="NotSupportedException">The stream does not support this operation.</exception>
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Clears all buffers for this stream and causes any buffered data to be written to the underlying device.
        /// </summary>
        /// <exception cref="NotSupportedException">The stream does not support this operation.</exception>
        public override void Flush()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Sets the position within the current stream.
        /// </summary>
        /// <param name="offset">A byte offset relative to the origin parameter.</param>
        /// <param name="origin">A value of type <see cref="SeekOrigin"/> indicating the reference point used to obtain the new position.</param>
        /// <returns>The new position within the current stream.</returns>
        /// <exception cref="NotSupportedException">The stream does not support this operation.</exception>
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Sets the length of the current stream.
        /// </summary>
        /// <param name="value">The desired length of the current stream in bytes.</param>
        /// <exception cref="NotSupportedException">The stream does not support this operation.</exception>
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
    }
}
