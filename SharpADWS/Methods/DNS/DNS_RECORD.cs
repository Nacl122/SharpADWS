using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace SharpADWS.Methods.DNS
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DNS_RECORD
    {
        public ushort DataLength;
        public ushort Type;
        public byte Version;
        public byte Rank;
        public ushort Flags;
        public uint Serial;
        public uint TtlSeconds;
        public uint Reserved;
        public uint TimeStamp;
        [MarshalAs(UnmanagedType.LPStr)]
        public byte[] Data;

        public const int Alignment = 1;

        public DNS_RECORD(byte[] recordData) : this()
        {
            if (recordData.Length < 15)
                throw new ArgumentException("DNS record data is too short.");
            DataLength = BitConverter.ToUInt16(recordData, 0);
            Type = BitConverter.ToUInt16(recordData, 2);
            Version = recordData[4];
            Rank = recordData[5];
            Flags = BitConverter.ToUInt16(recordData, 6);
            Serial = BitConverter.ToUInt32(recordData, 8);
            TtlSeconds = To_Large(BitConverter.ToUInt32(recordData, 12));
            Reserved = BitConverter.ToUInt32(recordData, 16);
            TimeStamp = BitConverter.ToUInt32(recordData, 20);
            if (recordData.Length > 24)
            {
                Data = new byte[recordData.Length - 24];
                Array.Copy(recordData, 24, Data, 0, Data.Length);
            }
            else
            {
                Data = new byte[0];
            }
        }

        public string GetIPv4Address()
        {
            if (Data.Length != 4 && this.Type != 1)
                throw new InvalidOperationException("Data does not represent an IPv4 address.");
            return new IPAddress(this.Data).ToString();
        }

        public MemoryStream ToStream()
        {
            using (MemoryStream stream = new MemoryStream())
            {
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    writer.Write(DataLength);
                    writer.Write(Type);
                    writer.Write(Version);
                    writer.Write(Rank);
                    writer.Write(Flags);
                    writer.Write(Serial);
                    writer.Write(To_Large(TtlSeconds));
                    writer.Write(Reserved);
                    writer.Write(TimeStamp);
                    if (Data != null)
                        writer.Write(Data);
                }
                return stream;
            }
        }
        public override string ToString()
        {
            byte[] byteArray = ToStream().ToArray();
            string result = "";
            foreach (byte b in byteArray)
            {
                result += (char)b;
            }
            return result;
        }

        public byte[] ToArray()
        {
            byte[] byteArray = ToStream().ToArray();
            return byteArray;
        }

        public uint To_Large(uint num)
        {
            byte[] ttlSecondsBytes = BitConverter.GetBytes(num);
            Array.Reverse(ttlSecondsBytes);
            return BitConverter.ToUInt32(ttlSecondsBytes, 0);
        }
    }
}
