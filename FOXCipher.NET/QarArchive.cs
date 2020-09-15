namespace FOXCipher.NET
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.IO;
    using System.Text;

    public class QarArchive : IDisposable
    {
        public static QarArchiveEntryNameMap DefaultHashMap { get; } = new QarArchiveEntryNameMap(); // DefaultHashLookup

        private readonly bool _leaveOpen;
        private readonly List<QarArchiveEntry> _entries;
        private readonly ReadOnlyCollection<QarArchiveEntry> _entriesCollection;
        private readonly Dictionary<string, QarArchiveEntry> _entriesDictionary;

        private Stream _stream;
        private BinaryReader _reader;

        private bool _isDisposed;
        private bool _sectionDataReaded;

        // header section
        private QarArchiveHeader _header;

        /// <summary>
        /// The archive flags.
        /// </summary>
        internal uint Flags => _header.Flags;

        /// <summary>
        /// The archive version.
        /// </summary>
        public int Version => (int)_header.Version; // 1 or 2

        /// <summary>
        /// The archive mode.
        /// </summary>
        public QarArchiveMode Mode { get; }

        /// <summary>
        /// The archive entries collection.
        /// </summary>
        public ReadOnlyCollection<QarArchiveEntry> Entries
        {
            get
            {
                if (Mode == QarArchiveMode.Create)
                    throw new NotSupportedException("TheaArchive does not support reading.");

                ThrowIfDisposed();

                EnsureReadSectionData();

                return _entriesCollection;
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="QarArchive"/> on the given stream.
        /// </summary>     
        /// <param name="stream">The input or output stream.</param>
        /// <param name="mode">See the description of the ZipArchiveMode enum. Read requires the stream to support reading, Create requires the stream to support writing, and Update requires the stream to support reading, writing, and seeking.</param>
        /// <param name="leaveOpen">true to leave the stream open upon disposing the <see cref="QarArchive"/>, otherwise false.</param>
        public QarArchive(Stream stream, QarArchiveMode mode = QarArchiveMode.Read, bool leaveOpen = false)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            switch (mode)
            {
                case QarArchiveMode.Create:
                    if (!stream.CanWrite)
                        throw new ArgumentException("The stream is already closed or does not support reading.");
                    break;

                case QarArchiveMode.Read:
                    if (!stream.CanRead)
                        throw new ArgumentException("The stream does not support reading.");
                    if (!stream.CanSeek)
                        throw new ArgumentException("The stream does not support seeking.");
                    break;

                case QarArchiveMode.Update:
                    // all the above
                    if (!stream.CanWrite)
                        throw new ArgumentException("The stream is already closed or does not support reading.");
                    if (!stream.CanRead)
                        throw new ArgumentException("The stream does not support reading.");
                    if (!stream.CanSeek)
                        throw new ArgumentException("The stream does not support seeking.");
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(mode));
            }

            _leaveOpen = leaveOpen;
            _entries = new List<QarArchiveEntry>();
            _entriesCollection = new ReadOnlyCollection<QarArchiveEntry>(_entries);
            _entriesDictionary = new Dictionary<string, QarArchiveEntry>();

            Mode = mode;

            Init(stream);
        }

        //
        void Init(Stream stream)
        {
            _stream = stream;


            if (Mode == QarArchiveMode.Read)
            {
                _reader = new BinaryReader(stream, Encoding.UTF8, _leaveOpen);

                // read the header first
                ReadHeader();
            }

            if (Mode == QarArchiveMode.Update)
            {
                if (_stream.Length > 0)
                {
                    _reader = new BinaryReader(stream, Encoding.UTF8, _leaveOpen);

                    // we can read something in here too
                    ReadHeader();

                    EnsureReadSectionData();
                }
            }

        }

        void ReadHeader()
        {
            if (!QarArchiveHeader.TryRead(_reader, out _header))
            {
                throw new InvalidDataException("The contents of the stream are not in the qar archive format.");
            }
        }

        //
        void EnsureReadSectionData()
        {
            if (!_sectionDataReaded)
            {
                ReadSectionData();
                _sectionDataReaded = true;
            }
        }

        void ReadSectionData()
        {
            // we do not check for stream positioning

            var reader = new SectionDataReader(_reader, (int)_header.Version);

            for (int i = 0; i < _header.FileCount; i++)
            {
                // each section is 8 bytes
                var section = reader.Next();

                var entry = new QarArchiveEntry(this, section);

                // here we make sure we have readed the header
                // this could be done lazely instead
                using (new StreamPositionPreservedWrapper(_stream))
                {
                    entry.EsnureReadHeader();
                }

                _entries.Add(entry);
            }

            // unknown section
            for (int i = 0; i < _header.UnknownCount; i++)
            {
                // each section is 16 bytes
                ulong l1 = _reader.ReadUInt64();
                ulong l2 = _reader.ReadUInt64();

                // just skip this bytes for now
            }
        }

        //
        public QarArchiveEntry CreateEntry(string entryName)
        {
            if (entryName == null)
                throw new ArgumentNullException(nameof(entryName));
            if (entryName.Length == 0)
                throw new ArgumentException("The entry name cannot be empty.", nameof(entryName));
            if (Mode == QarArchiveMode.Read)
                throw new NotSupportedException("The archive does not support writing.");

            ThrowIfDisposed();

            return null;
        }

        //
        internal Stream Open(long position = -1, long length = -1)
        {
            if (position > -1)
            {
                _stream.Position = position;

                // we want a section of the stream
                if (length > -1)
                    return new SectionStream(_stream, position, length);
            }

            // a special stream that cannot be disposed
            return new DisposeSafeStream(_stream);
        }

        //
        internal string GetFileNameFromHash(ulong hash)
        {
            DefaultHashMap.TryGetFileName(hash, out string name);
            DefaultHashMap.TryGetExtension(hash, out string ext);

            if (ext == null)
            {
                if (name == null)
                {
                    return hash.ToString("X8");
                }

                return name;
            }

            return name + "." + ext;
        }

        //
        internal void ThrowIfDisposed()
        {
            if (_isDisposed)
                throw new ObjectDisposedException(GetType().ToString());
        }

        #region IDisposable

        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !_isDisposed)
            {
                // always dispose our internal reader
                _reader?.Dispose();

                if (!_leaveOpen)
                {
                    _stream.Dispose();
                }

                _isDisposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
