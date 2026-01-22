using System;
using System.Linq;
using System.Security.Cryptography;

namespace ViewStateDecryptor.Validators
{
    // Some legacy algorithms have been replaces with HMACSHA1 under the hood
    internal class HMACSHA1Validator : Validator
    {
        public HMACSHA1Validator()
        {
            HashSize = 20;
        }

        public override bool Validate(byte[] data, byte[] key)
        {
            var expectedHash = new byte[HashSize];
            Array.Copy(data, data.Length - expectedHash.Length, expectedHash, 0, expectedHash.Length);
            data = data.Take(data.Length - expectedHash.Length).ToArray();
            using (var hmac = new HMACSHA1(key))
            {
                var computedHash = hmac.ComputeHash(data);
                return expectedHash.SequenceEqual(computedHash);
            }
        }
    }
}
