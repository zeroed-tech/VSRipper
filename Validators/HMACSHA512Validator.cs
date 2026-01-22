using System;
using System.Linq;
using System.Security.Cryptography;

namespace ViewStateDecryptor.Validators
{
    internal class HMACSHA512Validator : Validator
    {
        public HMACSHA512Validator()
        {
            HashSize = 64;
        }

        public override bool Validate(byte[] data, byte[] key)
        {
            var expectedHash = new byte[HashSize];
            Array.Copy(data, data.Length - expectedHash.Length, expectedHash, 0, expectedHash.Length);
            data = data.Take(data.Length - expectedHash.Length).ToArray();
            using (var hmac = new HMACSHA512(key))
            {
                var computedHash = hmac.ComputeHash(data);
                return expectedHash.SequenceEqual(computedHash);
            }
        }
    }
}
