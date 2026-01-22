using System;
using System.Collections.Generic;
using System.Text;

namespace ViewStateDecryptor.Validators
{
    internal abstract class Validator
    {
        public virtual string Name => GetType().Name.Replace("Validator", "");
        public int HashSize { get; protected set; }
        abstract public bool Validate(byte[] data, byte[] key);
    }
}
