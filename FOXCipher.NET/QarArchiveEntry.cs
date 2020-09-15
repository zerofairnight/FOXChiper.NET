namespace FOXCipher.NET
{
    using System.IO;

    public class QarArchiveEntry
    {
        private readonly QarArchive _archive;
        private readonly ulong _section;

        private bool _headerReaded; // if the header has been readed
        private QarArchiveEntryHeader header;

        /// <summary>
        /// The archive that the entry belongs to.
        /// </summary>
        public QarArchive Archive => _archive;

        /// <summary>
        /// The entry offset relative the the archive.
        /// Note: the offset starts from the header.
        /// </summary>
        internal long Offset
        {
            get
            {
                var block = _section >> 40;

                var blockShiftBits = (_archive.Flags & 0x800) > 0 ? 12 : 10;

                return (long)(block << blockShiftBits);
            }

        }

        /// <summary>
        /// The uncompressed size of the entry.
        /// </summary>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public long Length
        {
            get
            {
                EsnureReadHeader();

                return _archive.Version != 2 ? header.Size1 : header.Size2;
            }
        }

        /// <summary>
        /// The compressed size of the entry.
        /// </summary>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public long CompressedLength
        {
            get
            {
                EsnureReadHeader();

                return _archive.Version != 2 ? header.Size2 : header.Size1;
            }
        }

        /// <summary>
        /// Returns true if the entry contents has been compressed.
        /// </summary>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public bool Compressed
        {
            get
            {
                EsnureReadHeader();

                return Length != CompressedLength;
            }
        }

        /// <summary>
        /// The archive entry hash.
        /// </summary>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public ulong Hash
        {
            get
            {
                EsnureReadHeader();

                return header.Hash;
            }
        }

        /// <summary>
        /// The archive entry seed.
        /// </summary>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public ulong Seed
        {
            get
            {
                EsnureReadHeader();

                return header.Seed;
            }
        }

        /// <summary>
        /// The resolved full name from hash.
        /// </summary>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public string FullName => _archive.GetFileNameFromHash(Hash);

        /// <summary>
        /// The resolved file name from hash.
        /// </summary>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public string Name => Path.GetFileName(FullName);

        // the section contains a base offset and a hash 
        internal QarArchiveEntry(QarArchive archive, ulong section)
        {
            _archive = archive;
            _section = section;
        }

        /// <summary>
        /// Opens the entry from the qar archive.
        /// </summary>
        /// <returns>The stream that represents the contents of the entry.</returns>
        /// <exception cref="InvalidDataException">The contents of the stream are not in the qar archive format.</exception>
        public Stream Open()
        {
            EsnureReadHeader();

            // skip the entry header
            var stream = _archive.Open(Offset + 32, CompressedLength);

            return new QarArchiveEntryStreamReader(this, stream, header.Content);
        }

        //
        internal void EsnureReadHeader()
        {
            if (!_headerReaded)
            {
                ReadHeader();
                _headerReaded = true;
            }
        }

        // header is 32 bytes
        void ReadHeader()
        {
            // we cant read if the archive has been closed.
            _archive.ThrowIfDisposed();

            using (var stream = _archive.Open(Offset))
            using (var reader = new BinaryReader(stream))
            {
                if (!QarArchiveEntryHeader.TryRead(reader, _archive.Version, out header))
                {
                    throw new InvalidDataException("The contents of the stream are not in the qar archive format.");
                }
            }
        }
    }
}
