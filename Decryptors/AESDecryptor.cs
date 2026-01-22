using System.Security.Cryptography;

namespace VSRipper.Decryptors
{
    public class AESDecryptor : Decryptor
    {
        public override bool Decrypt(byte[] cipherText, byte[] key, out byte[] decrypted, bool isLegacy)
        {
            return Decrypt(Aes.Create(), cipherText, key, out decrypted, isLegacy);
        }
    }
}
