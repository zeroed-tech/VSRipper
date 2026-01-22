using System;
using System.Linq;
using System.Security.Cryptography;

namespace ViewStateDecryptor.Validators
{
    internal class MD5Validator : Validator
    {
        public MD5Validator()
        {
            HashSize = 16;
        }

        public override bool Validate(byte[] data, byte[] key)
        {
            var expectedHash = new byte[HashSize];
            Array.Copy(data, data.Length - expectedHash.Length, expectedHash, 0, expectedHash.Length);
            var toHash = new byte[data.Length + key.Length - expectedHash.Length];

            Array.Copy(data, 0, toHash, 0, data.Length - expectedHash.Length);
            Array.Copy(key, 0, toHash, data.Length - expectedHash.Length, key.Length);
            using (var md5 = MD5.Create())
            {
                var computedHash = md5.ComputeHash(toHash);

                return expectedHash.SequenceEqual(computedHash);
            }
        }
    }
}
