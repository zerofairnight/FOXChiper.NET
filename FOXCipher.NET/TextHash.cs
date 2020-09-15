namespace FOXCipher.NET
{
    using System;

    public static class TextHash
    {
        private const ulong MetaFlag = 0x4000000000000;
        private const ulong seed0 = 0x9ae16a3b2f90404f;

        public static ulong Hash(string value)
        {
            return CityHash.CityHash64WithSeeds(value, seed0, GetStringSeed(value)) & 0x3FFFFFFFFFFFF;
        }

        public static ulong HashFileName(string path)
        {
            bool meta = path.StartsWith("/Assets/") ? path.StartsWith("/Assets/tpptest") : true;

            path = NormalizeFileName(path);
            // path = RemoveExtension(path);

            var hash = Hash(path);

            return meta ? hash | MetaFlag : hash;
        }

        public static ulong HashFileNameWhitoutExtension(string path)
        {
            bool meta = path.StartsWith("/Assets/") ? path.StartsWith("/Assets/tpptest") : true;

            path = NormalizeFileName(path);
            path = RemoveExtension(path);

            var hash = Hash(path);

            return meta ? hash | MetaFlag : hash;
        }

        public static ulong GetStringSeed(string value)
        {
            byte[] seed1Bytes = new byte[sizeof(ulong)];

            for (int i = value.Length - 1, j = 0; i >= 0 && j < sizeof(ulong); i--, j++)
            {
                seed1Bytes[j] = Convert.ToByte(value[i]);
            }

            return BitConverter.ToUInt64(seed1Bytes, 0);
        }

        //
        private static string NormalizeFileName(string path)
        {
            if (path.StartsWith("/Assets/"))
            {
                path = path.Substring("/Assets/".Length);
            }

            return path.TrimStart('/');
        }

        private static string RemoveExtension(string path)
        {
            int index = path.IndexOf('.');
            return index == -1 ? path : path.Substring(0, index);
        }
    }
}
