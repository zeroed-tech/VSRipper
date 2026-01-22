using System;
using System.Linq;
using System.Security.Cryptography;

namespace ViewStateDecryptor.Validators
{
    internal class SHA1Validator : Validator
    {
        public SHA1Validator()
        {
            HashSize = 20;
        }

        public override bool Validate(byte[] data, byte[] key)
        {
            var expectedHash = new byte[HashSize];
            Array.Copy(data, data.Length - expectedHash.Length, expectedHash, 0, expectedHash.Length);
            var toHash = new byte[data.Length + key.Length - expectedHash.Length];

            Array.Copy(data, 0, toHash, 0, data.Length - expectedHash.Length);
            Array.Copy(key, 0, toHash, data.Length - expectedHash.Length, key.Length);

            using (var sha1 = SHA1.Create())
            {
                var computedHash = sha1.ComputeHash(toHash);

                return expectedHash.SequenceEqual(computedHash);
            }
        }
    }
}
