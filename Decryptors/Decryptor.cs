
using System;
using System.Security.Cryptography;

namespace VSRipper.Decryptors
{
    public abstract class Decryptor
    {
        public virtual string Name => GetType().Name.Replace("Decryptor", "");
        abstract public bool Decrypt(byte[] cipherText, byte[] key, out byte[] decrypted, bool isLegacy);

        /// <summary>
        /// Use the passed in algorithm and key to decrypt the cipher text
        /// </summary>
        /// <param name="algo"></param>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="decrypted"></param>
        /// <param name="isLegacy"></param>
        /// <returns>True if the value was successfully decrypted and contains a valid view state</returns>
        protected bool Decrypt(SymmetricAlgorithm algo, byte[] cipherText, byte[] key, out byte[] decrypted, bool isLegacy)
        {
            try
            {
                algo.Key = key;
                // We extract the key size after setting the key as some algorithms support multiple key sizes and may default to the wrong value
                // For viewstate, all algorithms use a key size of 24 bytes except DES which uses 8
                var keySize = algo.KeySize / 8;
                int ivSize = algo.BlockSize / 8;
                
                
                byte[] iv = new byte[ivSize];
                // Legacy viewstates have a static IV of all zeros whilst modern have an IV prepended to the cipher text
                if (!isLegacy)
                {
                    Buffer.BlockCopy(cipherText, 0, iv, 0, ivSize);
                }
                algo.IV = iv;
                using (ICryptoTransform decryptor = algo.CreateDecryptor())
                {
                    // Skip over the IV if present
                    var skip = isLegacy ? 0 : ivSize;

                    // Decrypt the cipher text
                    var buf = decryptor.TransformFinalBlock(cipherText, skip, cipherText.Length - skip);

                    // Legacy viewstates have keysize bytes of random junk prepended to the plaintext whilst modern have nothing
                    skip = isLegacy ? keySize : 0;
                    
                    decrypted = new byte[buf.Length - skip];
                    Buffer.BlockCopy(buf, skip, decrypted, 0, decrypted.Length);
                    // Make sure the buffer contains a valid view state
                    return decrypted.Length >= 2 && decrypted[0] == 0xFF && decrypted[1] == 0x01;
                    
                }
            }
            catch { }// Ignore any errors, we may be using the wrong algorithm
            decrypted = new byte[0];
            return false;
        }
    }
}
