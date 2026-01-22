using System;
using System.Security.Cryptography;

namespace VSRipper.Decryptors
{
    public class DESDecryptor : Decryptor
    {
        public override bool Decrypt(byte[] cipherText, byte[] key, out byte[] decrypted, bool isLegacy)
        {
            // DES only supports 8 byte keys
            var innerKey = new byte[8];
            Buffer.BlockCopy(key, 0, innerKey, 0, 8);

            return Decrypt(DES.Create(), cipherText, innerKey, out decrypted, isLegacy);
        }
    }
}
