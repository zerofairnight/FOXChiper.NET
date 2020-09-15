namespace FOXCipher.NET
{
    using System;
    using System.Text;
    using uint128 = UInt128;
    using uint32 = System.UInt32;
    using uint64 = System.UInt64;
    using uint8 = System.Byte;

    // reduced version from https://github.com/Atvaark/CityHash
    internal static class CityHash
    {
        // Some primes between 2^63 and 2^64 for various uses.
        private const uint64 K0 = 0xc3a5c85c97cb3127;
        private const uint64 K1 = 0xb492b66fbe98f273;
        private const uint64 K2 = 0x9ae16a3b2f90404f;
        private const uint64 K3 = 0xc949d7c7509e6557;
        private static bool BigEndian;

        //
        public static uint64 CityHash64WithSeeds(string value, uint64 seed0, uint64 seed1)
        {
            uint128 x = new uint128(CityHash64(Encoding.UTF8.GetBytes(value)) - seed0, seed1);

            // Murmur-inspired hashing.
            const ulong kMul = 0x9ddfea08eb382d69;
            ulong a = (x.Low ^ x.High) * kMul;
            a ^= (a >> 47);
            ulong b = (x.High ^ a) * kMul;
            b ^= (b >> 47);
            b *= kMul;

            return b;
        }

        private static uint64 CityHash64(byte[] s)
        {
            int len = s.Length;
            if (len <= 32)
            {
                if (len <= 16)
                {
                    return HashLen0To16(s, 0);
                }
                return HashLen17To32(s);
            }
            if (len <= 64)
            {
                return HashLen33To64(s);
            }


            // For strings over 64 bytes we hash the end first, and then as we
            // loop we keep 56 bytes of state: v, w, x, y, and z.
            uint64 x = Fetch64(s, len - 40);
            uint64 y = Fetch64(s, len - 16) + Fetch64(s, len - 56);
            uint64 z = HashLen16(Fetch64(s, len - 48) + (ulong)len, Fetch64(s, len - 24));
            uint128 v = WeakHashLen32WithSeeds(s, len - 64, (ulong)len, z);
            uint128 w = WeakHashLen32WithSeeds(s, len - 32, y + K1, x);
            x = x * K1 + Fetch64(s, 0);

            // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
            len = (s.Length - 1) & ~63;
            int offset = 0;
            do
            {
                x = Rotate(x + y + v.Low + Fetch64(s, offset + 8), 37) * K1;
                y = Rotate(y + v.High + Fetch64(s, offset + 48), 42) * K1;
                x ^= w.High;
                y += v.Low + Fetch64(s, offset + 40);
                z = Rotate(z + w.Low, 33) * K1;
                v = WeakHashLen32WithSeeds(s, offset, v.High * K1, x + w.Low);
                w = WeakHashLen32WithSeeds(s, offset + 32, z + w.High, y + Fetch64(s, offset + 16));

                var temp = z;
                z = x;
                x = temp;

                offset += 64;
                len -= 64;
            } while (len != 0);

            return HashLen16(
                HashLen16(v.Low, w.Low) + ShiftMix(y) * K1 + z,
                HashLen16(v.High, w.High) + x
            );
        }

        private static uint64 RotateByAtLeast1(uint64 val, int shift)
        {
            return (val >> shift) | (val << (64 - shift));
        }

        private static uint bswap_32(uint x)
        {
            byte[] bytes = BitConverter.GetBytes(x);
            Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

        private static ulong bswap_64(ulong x)
        {
            byte[] bytes = BitConverter.GetBytes(x);
            Array.Reverse(bytes);
            return BitConverter.ToUInt64(bytes, 0);
        }

        private static uint64 Fetch64(byte[] p, int index)
        {
            ulong x = BitConverter.ToUInt64(p, index);
            return BigEndian ? bswap_64(x) : x;
        }

        private static uint64 Fetch64(byte[] p, uint index)
        {
            return Fetch64(p, (int)index);
        }

        private static uint32 Fetch32(byte[] p, int index)
        {
            uint x = BitConverter.ToUInt32(p, index);
            return BigEndian ? bswap_32(x) : x;
        }

        private static uint64 Rotate(uint64 val, int shift)
        {
            // Avoid shifting by 64: doing so yields an undefined result.
            return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
        }

        private static uint64 ShiftMix(uint64 val)
        {
            return val ^ (val >> 47);
        }

        private static uint64 HashLen16(uint64 u, uint64 v)
        {
            uint128 x = new uint128(u, v);

            // Murmur-inspired hashing.
            const ulong kMul = 0x9ddfea08eb382d69;
            ulong a = (x.Low ^ x.High) * kMul;
            a ^= (a >> 47);
            ulong b = (x.High ^ a) * kMul;
            b ^= (b >> 47);
            b *= kMul;
            return b;
        }

        private static uint64 HashLen0To16(byte[] s, int offset)
        {
            int len = s.Length - offset;
            if (len > 8)
            {
                uint64 a = Fetch64(s, offset);
                uint64 b = Fetch64(s, offset + len - 8);
                return HashLen16(a, RotateByAtLeast1(b + (ulong)len, len)) ^ b;
            }
            if (len >= 4)
            {
                uint64 a = Fetch32(s, offset);
                return HashLen16((uint)len + (a << 3), Fetch32(s, offset + len - 4));
            }
            if (len > 0)
            {
                uint8 a = s[offset];
                uint8 b = s[offset + (len >> 1)];
                uint8 c = s[offset + (len - 1)];
                uint32 y = a + ((uint32)b << 8);
                uint32 z = (uint)len + ((uint32)c << 2);
                return ShiftMix(y * K2 ^ z * K3) * K2;
            }
            return K2;
        }

        private static uint64 HashLen17To32(byte[] s)
        {
            uint len = (uint)s.Length;
            uint64 a = Fetch64(s, 0) * K1;
            uint64 b = Fetch64(s, 8);
            uint64 c = Fetch64(s, len - 8) * K2;
            uint64 d = Fetch64(s, len - 16) * K0;

            return HashLen16(Rotate(a - b, 43) + Rotate(c, 30) + d, a + Rotate(b ^ K3, 20) - c + len);
        }

        private static uint128 WeakHashLen32WithSeeds(byte[] s, int offset, uint64 a, uint64 b)
        {
            ulong z = Fetch64(s, offset + 24);
            a += Fetch64(s, offset);
            b = Rotate(b + a + z, 21);
            uint64 c = a;
            a += Fetch64(s, offset + 8);
            a += Fetch64(s, offset + 16);
            b += Rotate(a, 44);
            return new uint128(a + z, b + c);
        }

        private static uint64 HashLen33To64(byte[] s)
        {
            uint len = (uint)s.Length;
            uint64 z = Fetch64(s, 24);
            uint64 a = Fetch64(s, 0) + (len + Fetch64(s, len - 16)) * K0;
            uint64 b = Rotate(a + z, 52);
            uint64 c = Rotate(a, 37);
            a += Fetch64(s, 8);
            c += Rotate(a, 7);
            a += Fetch64(s, 16);
            uint64 vf = a + z;
            uint64 vs = b + Rotate(a, 31) + c;
            a = Fetch64(s, 16) + Fetch64(s, len - 32);
            z = Fetch64(s, len - 8);
            b = Rotate(a + z, 52);
            c = Rotate(a, 37);
            a += Fetch64(s, len - 24);
            c += Rotate(a, 7);
            a += Fetch64(s, len - 16);
            uint64 wf = a + z;
            uint64 ws = b + Rotate(a, 31) + c;
            uint64 r = ShiftMix((vf + ws) * K2 + (wf + vs) * K0);
            return ShiftMix(r * K0 + vs) * K2;
        }
    }

    internal class UInt128
    {
        public UInt128()
        {
        }

        public UInt128(UInt64 low, UInt64 high)
        {
            Low = low;
            High = high;
        }

        public UInt64 Low { get; set; }
        public UInt64 High { get; set; }

        protected bool Equals(UInt128 other)
        {
            return Low == other.Low && High == other.High;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((UInt128)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (Low.GetHashCode() * 397) ^ High.GetHashCode();
            }
        }
    }
}

