using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// All code in this file has been taked from the .NET framework and modified to work without several ASP.NET classes
namespace VSRipper
{
    internal static class ModernKeyGenerator
    {
        private static CryptographicKey GenerateCryptographicKey(CryptographicKey autogenKey, int autogenKeyOffset, int autogenKeyCount, bool isolateByApps, bool isolateByAppId, string appName, string appId)
        {
            CryptographicKey cryptographicKey = autogenKey.ExtractBits(autogenKeyOffset, autogenKeyCount);
            List<string> list = new List<string>();
            if (isolateByApps)
            {
                list.Add("IsolateApps: " + appName);
            }
            if (isolateByAppId)
            {
                list.Add("IsolateByAppId: " + appId);
            }
            Purpose purpose = new Purpose("MachineKeyDerivation", list.ToArray());
            return SP800_108.DeriveKey(cryptographicKey, purpose);
        }

        public static CryptographicKey GetEncryptionKey(byte[] autoGenKey, bool isolateByApps, bool isolateByAppId, string appName, string appId) 
            => GenerateCryptographicKey(new CryptographicKey(autoGenKey), 0, 256, isolateByApps, isolateByAppId, appName, appId);

        public static CryptographicKey GetValidationKey(byte[] autoGenKey, bool isolateByApps, bool isolateByAppId, string appName, string appId)
            => GenerateCryptographicKey(new CryptographicKey(autoGenKey), 256, 256, isolateByApps, isolateByAppId, appName, appId);
    }

    internal static class SP800_108
    {
        public static CryptographicKey DeriveKey(CryptographicKey keyDerivationKey, Purpose purpose)
        {
            CryptographicKey cryptographicKey;
            using (HMACSHA512 hmacsha = new HMACSHA512(keyDerivationKey.GetKeyMaterial()))
            {
                byte[] label;
                byte[] context;
                purpose.GetKeyDerivationParameters(out label, out context);
                byte[] array3 = SP800_108.DeriveKeyImpl(hmacsha, label, context, keyDerivationKey.KeyLength);
                cryptographicKey = new CryptographicKey(array3);
            }
            return cryptographicKey;
        }

        private static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
        {
            int labelLen = ((label != null) ? label.Length : 0);
            int contextLen = ((context != null) ? context.Length : 0);
            checked
            {
                byte[] toHash = new byte[4 + labelLen + 1 + contextLen + 4];
                if (labelLen != 0)
                {
                    Buffer.BlockCopy(label, 0, toHash, 4, labelLen);
                }
                if (contextLen != 0)
                {
                    Buffer.BlockCopy(context, 0, toHash, 5 + labelLen, contextLen);
                }
                SP800_108.WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, toHash, 5 + labelLen + contextLen);
                int num3 = 0;
                int i = keyLengthInBits / 8;
                byte[] outputHash = new byte[i];
                uint iteration = 1U;
                while (i > 0)
                {
                    SP800_108.WriteUInt32ToByteArrayBigEndian(iteration, toHash, 0);
                    byte[] hash = hmac.ComputeHash(toHash);
                    int num5 = Math.Min(i, hash.Length);
                    Buffer.BlockCopy(hash, 0, outputHash, num3, num5);
                    num3 += num5;
                    i -= num5;
                    iteration += 1U;
                }
                return outputHash;
            }
        }

        private static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }
    }

    internal sealed class CryptographicKey
    {
        public CryptographicKey(byte[] keyMaterial)
        {
            this._keyMaterial = keyMaterial;
        }

        public int KeyLength
        {
            get
            {
                return checked(this._keyMaterial.Length * 8);
            }
        }

        public CryptographicKey ExtractBits(int offset, int count)
        {
            int num = offset / 8;
            int num2 = count / 8;
            byte[] array = new byte[num2];
            Buffer.BlockCopy(this._keyMaterial, num, array, 0, num2);
            return new CryptographicKey(array);
        }

        public byte[] GetKeyMaterial()
        {
            return this._keyMaterial;
        }

        private readonly byte[] _keyMaterial;
    }

    internal sealed class Purpose
    {
        public Purpose(string primaryPurpose, params string[] specificPurposes)
        {
            this.PrimaryPurpose = primaryPurpose;
            this.SpecificPurposes = specificPurposes ?? new string[0];
        }
    
        internal Purpose AppendSpecificPurpose(string specificPurpose)
        {
            string[] array = new string[this.SpecificPurposes.Length + 1];
            Array.Copy(this.SpecificPurposes, array, this.SpecificPurposes.Length);
            array[array.Length - 1] = specificPurpose;
            return new Purpose(this.PrimaryPurpose, array);
        }

        public CryptographicKey GetDerivedEncryptionKey(CryptographicKey encryptionKey) => SP800_108.DeriveKey(encryptionKey, this);

        public CryptographicKey GetDerivedValidationKey(CryptographicKey validationKey) => SP800_108.DeriveKey(validationKey, this);

        internal void GetKeyDerivationParameters(out byte[] label, out byte[] context)
        {
            if (this._derivedKeyLabel == null)
            {
                this._derivedKeyLabel = new UTF8Encoding(false, true).GetBytes(this.PrimaryPurpose);
            }
            if (this._derivedKeyContext == null)
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (BinaryWriter binaryWriter = new BinaryWriter(memoryStream, new UTF8Encoding(false, true)))
                    {
                        foreach (string text in this.SpecificPurposes)
                        {
                            binaryWriter.Write(text);
                        }
                        this._derivedKeyContext = memoryStream.ToArray();
                    }
                }
            }
            label = this._derivedKeyLabel;
            context = this._derivedKeyContext;
        }

        public readonly string PrimaryPurpose;

        public readonly string[] SpecificPurposes;

        private byte[] _derivedKeyLabel;

        private byte[] _derivedKeyContext;
    }
}
