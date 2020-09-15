namespace FOXCipher.NET
{
    using System.Collections.Generic;

    public class QarArchiveEntryNameMap
    {
        const ulong FileNamePart = 0x3FFFFFFFFFFFF;
        const ulong ExtensionPart = 0x1FFF;

        private readonly Dictionary<ulong, string> hashToFileName = new Dictionary<ulong, string>();
        private readonly Dictionary<ulong, string> hashToExtension = new Dictionary<ulong, string>();

        public void AddFileName(string name)
        {
            ulong hash = Hash(name, FileNamePart);

            if (!hashToFileName.ContainsKey(hash))
                hashToFileName.Add(hash, name);
        }

        public void AddFileExtension(string name)
        {
            ulong hash = Hash(name, ExtensionPart);

            if (!hashToExtension.ContainsKey(hash))
                hashToExtension.Add(hash, name);
        }

        public bool TryGetFileName(ulong hash, out string name)
        {
            hash = hash & 0x3FFFFFFFFFFFF;

            if (hashToFileName.TryGetValue(hash, out name))
                return true;

            name = hash.ToString("x");
            return false;
        }

        public bool TryGetExtension(ulong hash, out string name)
        {
            hash = hash >> 51;

            if (hashToExtension.TryGetValue(hash, out name))
                return true;

            name = hash.ToString("x");
            return false;
        }

        private ulong Hash(string text, ulong part)
        {
            return TextHash.HashFileName(text) & part;
        }
    }

}
