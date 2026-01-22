using System.Security.Cryptography;

namespace VSRipper.Decryptors
{
    public class TripleDESDecryptor : Decryptor
    {
        public override bool Decrypt(byte[] cipherText, byte[] key, out byte[] decrypted, bool isLegacy)
        {
            return Decrypt(TripleDES.Create(), cipherText, key, out decrypted, isLegacy);
        }
    }
}
