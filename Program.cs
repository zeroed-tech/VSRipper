using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using ViewStateDecryptor.Validators;
using VSRipper;
using VSRipper.Decryptors;


internal class Program
{
    [Verb("bruteforce", HelpText = "Given a list of autogen keys, attempt to validate and decrypt a view state using all combinations of validation and decryption algorithms")]
    public class BruteforceOptions
    {
        [Option(Default = true, HelpText = "Should legacy machine keys be generated?")]
        public bool GenerateLegacy { get; set; }

        [Option(Default = true, HelpText = "Should modern machine keys be generated?")]
        public bool GenerateModern { get; set; }

        [Option(Required = true, HelpText = "A comma separated list of autogen keys")]
        public IEnumerable<string> AutogenKeys { get; set; }

        [Option(Required = true, HelpText = "The path to the web application targeted")]
        public string Webapp { get; set; }

        [Option(Required = true, HelpText = "The ID of the application targeted")]
        public string AppId { get; set; }

        [Option(Required = true, HelpText = "The page the target view state was generated for")]
        public string Page { get; set; }

        [Option(Required = true, HelpText = "The path to a file containing the view state message to decrypt")]
        public string ViewState { get; set; }

        [Option(Required = false, HelpText = "The view state user key for the target application")]
        public string UserKey { get; set; }

        [Option(Default = false, HelpText = "Set to true if your view state message is url encoded")]
        public bool UrlEncoded { get; set; }

        [Option(Required = false, HelpText = "A file to write the decrypted viewstate to")]
        public string OutputFile { get; set; }

        [Option(Default = false, HelpText = "Print all combinations tested")]
        public bool Verbose { get; set; }
    }

    [Verb("decrypt", HelpText = "Decrypt a view state message using provided information")]
    public class DecryptOptions
    {
        public enum DecryptionAlgorithm
        {
            AES,
            DES,
            TripleDES,
            Auto
        }

        public enum ValidationAlgorithm
        {
            HMACSHA1,
            HMACSHA256,
            HMACSHA384,
            HMACSHA512,
            MD5,
            SHA1
        }

        [Option(Default = false, HelpText = "Use legacy crypto")]
        public bool IsLegacy { get; set; }

        [Option(Required = true, HelpText = "The validation key from the target server")]
        public string DecryptionKey { get; set; }

        [Option(Required = true, HelpText = "The decryption key from the target server")]
        public string ValidationKey { get; set; }

        [Option(Default = false, HelpText = "Set to skip payload validation")]
        public bool SkipValidation { get; set; }

        [Option(Required = true, HelpText = "The path to the web application targeted")]
        public string Webapp { get; set; }

        [Option(Required = true, HelpText = "The page the target view state was generated for")]
        public string Page { get; set; }

        [Option(Required = true, HelpText = "The path to a file containing the view state message to decrypt")]
        public string ViewState { get; set; }

        [Option(Required = false, HelpText = "The view state user key for the target application")]
        public string UserKey { get; set; }

        [Option(Default = false, HelpText = "Set to true if your view state message is url encoded")]
        public bool UrlEncoded { get; set; }

        [Option(Required = false, HelpText = "A file to write the decrypted viewstate to")]
        public string OutputFile { get; set; }

        [Option(Default = false, HelpText = "Print all combinations tested")]
        public bool Verbose { get; set; }

        [Option(Required = true, Default = DecryptionAlgorithm.Auto, HelpText = "The decryption algorithm to use")]
        public DecryptionAlgorithm Decryptor { get; set; }
        
        [Option(Required = true, Default = ValidationAlgorithm.HMACSHA256, HelpText = "The validation algorithm to use")]
        public ValidationAlgorithm Validator { get; set; }
    }

    private static bool VerboseLogging = false;

    private static List<Validator> Validators = new List<Validator>
            {
                new HMACSHA1Validator(),
                new HMACSHA256Validator(),
                new HMACSHA384Validator(),
                new HMACSHA512Validator(),
                new MD5Validator(),
                new SHA1Validator()
            };

    private static List<Decryptor> Decryptors = new List<Decryptor>
            {
                new AESDecryptor(),
                new DESDecryptor(),
                new TripleDESDecryptor()
            };

    static void Main(string[] args)
    {
        Parser.Default.ParseArguments<BruteforceOptions, DecryptOptions>(args)
        .MapResult(
          (BruteforceOptions opts) => RunBruteForce(opts),
          (DecryptOptions opts) => RunDecrypt(opts),
          errs => 1);
    }

    static int RunBruteForce(BruteforceOptions options)
    {
        if(!File.Exists(options.ViewState))
        {
            Console.WriteLine("--viewState file does not exist: " + options.ViewState);
            return -1;
        }
        VerboseLogging = options.Verbose;
        var autogenKeysList = options.AutogenKeys.Select(k => HexStringToBytes(k)).ToList();
        var appName = options.Webapp;
        var appId = options.AppId;
        var strPayload = File.ReadAllText(options.ViewState);
        var page = options.Page.TrimStart(new char[] { '/' });
        var viewStateUserKey = options.UserKey;

        if (options.UrlEncoded)
        {
            strPayload = Uri.UnescapeDataString(strPayload);
        }
        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(strPayload);
        }catch(Exception)
        {
            Console.WriteLine("Failed to base64 decode view state message, try using --urlencoded");
            return -1;
        }


        if (options.GenerateLegacy)
        {
            LogVerbose("Testing legacy crypto configurations");
            foreach (var (validationKey, decryptionKey) in GenerateLegacyKeys(autogenKeysList, appName, appId))
            {
                if (!TestValidationKey(validationKey, ref payload, true)) continue;

                if(!AttemptDecryption(decryptionKey, payload, true, options.OutputFile))
                {
                    Console.WriteLine("Decryption failed");
                    return -1;
                }
                return 0;
            }
        }
        if (options.GenerateModern)
        {
            LogVerbose("Testing modern crypto configurations");
            foreach (var (validationKey, decryptionKey) in GenerateModernKeys(autogenKeysList, appName, appId, page, viewStateUserKey))
            {
                if (!TestValidationKey(validationKey, ref payload, false)) continue;

                // Attempt to decrypt the payload. Return if we fail
                if(!AttemptDecryption(decryptionKey, payload, false, options.OutputFile))
                {
                    Console.WriteLine("Decryption failed");
                    return -1;
                }
                return 0;
            }
        }

        Console.WriteLine("No valid validator found");
        return -1;

    }

    static int RunDecrypt(DecryptOptions options)
    {
        if (!File.Exists(options.ViewState))
        {
            Console.WriteLine("--viewState file does not exist: " + options.ViewState);
            return -1;
        }
        VerboseLogging = options.Verbose;

        var validationKey = HexStringToBytes(options.ValidationKey);
        var decryptionKey = HexStringToBytes(options.DecryptionKey);

        var validationAlgorithm = Validators.FirstOrDefault(v => v.Name.Equals(options.Validator.ToString(), StringComparison.InvariantCultureIgnoreCase)) ?? Validators[1]; // Default to HMACSHA256
        var decryptionAlgorithm = Decryptors.FirstOrDefault(d => d.Name.Equals(options.Decryptor.ToString(), StringComparison.InvariantCultureIgnoreCase)) ?? Decryptors[0]; // Default to AES

        var appName = options.Webapp;
        var strPayload = File.ReadAllText(options.ViewState);
        var page = options.Page.TrimStart(new char[] { '/' });
        var viewStateUserKey = options.UserKey;

        if (options.UrlEncoded)
        {
            strPayload = Uri.UnescapeDataString(strPayload);
        }
        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(strPayload);
        }
        catch (Exception)
        {
            Console.WriteLine("Failed to base64 decode view state message, try using --urlencoded");
            return -1;
        }

        if (!options.IsLegacy)
        {
            // Derive keys
            var purpose = new Purpose("WebForms.HiddenFieldPageStatePersister.ClientState");
            purpose = purpose.AppendSpecificPurpose("TemplateSourceDirectory: " + appName);
            purpose = purpose.AppendSpecificPurpose("Type: " + (page.ToUpperInvariant().Replace(".", "_")));
            if (!string.IsNullOrEmpty(viewStateUserKey))
            {
                purpose = purpose.AppendSpecificPurpose("ViewStateUserKey: " + viewStateUserKey);
            }

            validationKey = purpose.GetDerivedValidationKey(new CryptographicKey(validationKey)).GetKeyMaterial();
            decryptionKey = purpose.GetDerivedEncryptionKey(new CryptographicKey(decryptionKey)).GetKeyMaterial();
        }

        if (!options.SkipValidation)
        {
            if (!validationAlgorithm.Validate(payload, validationKey))
            {
                Console.WriteLine("Validation failed");
                return -1;
            }
        }

        // Drop hash size from payload
        payload = payload.Take(payload.Length - validationAlgorithm.HashSize).ToArray();
        if (!decryptionAlgorithm.Decrypt(payload, decryptionKey, out byte[] decryptedBytes, options.IsLegacy))
        {
            Console.WriteLine("Decryption failed");
            return -1;
        }
        else
        {
            if (!string.IsNullOrEmpty(options.OutputFile))
            {
                File.WriteAllBytes(options.OutputFile, decryptedBytes);
                Console.WriteLine($"Decrypted payload written to {options.OutputFile}");
            }
            else
            {
                Console.WriteLine("Decrypted payload: \n" + Encoding.UTF8.GetString(decryptedBytes));
            }
            return 0;
        }
    }

    private static bool TestValidationKey(byte[] key, ref byte[] payload, bool isLegacy)
    {
        foreach (var validator in Validators)
        {
            LogVerbose($"Trying validator:  {validator.Name} with key {BitConverter.ToString(key).Replace("-", string.Empty)}");
            if (!validator.Validate(payload, key)) continue;

            Console.WriteLine($"Successfully validated {(isLegacy ? "Legacy" : "Modern")} payload using {validator.Name} with validation key {BitConverter.ToString(key).Replace("-", string.Empty)}");
            // Drop hash size from payload
            payload = payload.Take(payload.Length - validator.HashSize).ToArray();
            return true;
        }
        return false;
    }

    private static bool AttemptDecryption(byte[] key, byte[] payload, bool isLegacy, string outFile)
    {
        // Attempt to decrypt the payload
        foreach (var decryptor in Decryptors)
        {
            if (!decryptor.Decrypt(payload, key, out byte[] decryptedBytes, isLegacy)) continue;

            Console.WriteLine($"Successfully decrypted {(isLegacy ? "Legacy" : "Modern")} payload using {decryptor.Name} with decryption key {BitConverter.ToString(key).Replace("-", string.Empty)}");
            if (!string.IsNullOrEmpty(outFile))
            {
                File.WriteAllBytes(outFile, decryptedBytes);
                Console.WriteLine($"Decrypted payload written to {outFile}");
            }
            else
            {
                Console.WriteLine("Decrypted payload: \n" + Encoding.UTF8.GetString(decryptedBytes));
            }
            return true;
        }
        return false;
    }


    private static void LogVerbose(string message)
    {
        if (VerboseLogging)
        {
            Console.WriteLine(message);
        }
    }

    static IEnumerable<(byte[] validationKey, byte[] decryptionKey)> GenerateLegacyKeys(List<byte[]> autogenKeysList, string appName, string appId)
    {
        int validationKeySize = 64;
        int decryptionKeySize = 24;

        foreach (var autogenKeys in autogenKeysList)
        {
            byte[] validationKeyAuto = new byte[validationKeySize];
            byte[] decryptionKeyAuto = new byte[decryptionKeySize];
            Buffer.BlockCopy(autogenKeys, 0, validationKeyAuto, 0, validationKeySize);
            Buffer.BlockCopy(autogenKeys, validationKeySize, decryptionKeyAuto, 0, decryptionKeySize);

            int dwCode3 = StringComparer.InvariantCultureIgnoreCase.GetHashCode(appName);
            //Console.WriteLine("AppName Hash: " + dwCode3.ToString("X8"));

            byte[] _validationKeyAutoAppSpecific = validationKeyAuto.ToArray();
            _validationKeyAutoAppSpecific[0] = (byte)(dwCode3 & 0xff);
            _validationKeyAutoAppSpecific[1] = (byte)((dwCode3 & 0xff00) >> 8);
            _validationKeyAutoAppSpecific[2] = (byte)((dwCode3 & 0xff0000) >> 16);
            _validationKeyAutoAppSpecific[3] = (byte)((dwCode3 & 0xff000000) >> 24);

            byte[] _decryptionKeyAutoAutoAppSpecific = decryptionKeyAuto.ToArray();
            _decryptionKeyAutoAutoAppSpecific[0] = (byte)(dwCode3 & 0xff);
            _decryptionKeyAutoAutoAppSpecific[1] = (byte)((dwCode3 & 0xff00) >> 8);
            _decryptionKeyAutoAutoAppSpecific[2] = (byte)((dwCode3 & 0xff0000) >> 16);
            _decryptionKeyAutoAutoAppSpecific[3] = (byte)((dwCode3 & 0xff000000) >> 24);

            // Yield the IsolateApps keys
            yield return (_validationKeyAutoAppSpecific, _decryptionKeyAutoAutoAppSpecific);


            int dwCode4 = StringComparer.InvariantCultureIgnoreCase.GetHashCode(appId);

            byte[] _validationKeyAutoAppIdSpecific = validationKeyAuto.ToArray();
            _validationKeyAutoAppIdSpecific[4] = (byte)(dwCode4 & 0xff);
            _validationKeyAutoAppIdSpecific[5] = (byte)((dwCode4 & 0xff00) >> 8);
            _validationKeyAutoAppIdSpecific[6] = (byte)((dwCode4 & 0xff0000) >> 16);
            _validationKeyAutoAppIdSpecific[7] = (byte)((dwCode4 & 0xff000000) >> 24);


            byte[] _decryptionKeyAutoAutoAppIdSpecific = decryptionKeyAuto.ToArray();
            _decryptionKeyAutoAutoAppIdSpecific[4] = (byte)(dwCode4 & 0xff);
            _decryptionKeyAutoAutoAppIdSpecific[5] = (byte)((dwCode4 & 0xff00) >> 8);
            _decryptionKeyAutoAutoAppIdSpecific[6] = (byte)((dwCode4 & 0xff0000) >> 16);
            _decryptionKeyAutoAutoAppIdSpecific[7] = (byte)((dwCode4 & 0xff000000) >> 24);

            // Yield the IsolateByAppId keys
            yield return (_validationKeyAutoAppIdSpecific, _decryptionKeyAutoAutoAppIdSpecific);
        }
    }

    static IEnumerable<(byte[] validationKey, byte[] decryptionKey)> GenerateModernKeys(List<byte[]> autogenKeysList, string appName, string appId, string page, string viewStateUserKey)
    {
        int validationKeySize = 64;
        int decryptionKeySize = 24;

        var purpose = new Purpose("WebForms.HiddenFieldPageStatePersister.ClientState");
        purpose = purpose.AppendSpecificPurpose("TemplateSourceDirectory: " + appName);
        purpose = purpose.AppendSpecificPurpose("Type: " + (page.ToUpperInvariant().Replace(".", "_")));
        if(!string.IsNullOrEmpty(viewStateUserKey))
        {
            purpose = purpose.AppendSpecificPurpose("ViewStateUserKey: " + viewStateUserKey);
        }

        foreach (var autogenKeys in autogenKeysList)
        {
            byte[] validationKeyAuto = new byte[validationKeySize];
            byte[] decryptionKeyAuto = new byte[decryptionKeySize];
            Buffer.BlockCopy(autogenKeys, 0, validationKeyAuto, 0, validationKeySize);
            Buffer.BlockCopy(autogenKeys, validationKeySize, decryptionKeyAuto, 0, decryptionKeySize);
            {
                var masterValidationKey = ModernKeyGenerator.GetValidationKey(autogenKeys, true, false, appName, "");
                var masterDecryptionKey = ModernKeyGenerator.GetEncryptionKey(autogenKeys, true, false, appName, "");

                var derivedValidationKey = purpose.GetDerivedValidationKey(masterValidationKey).GetKeyMaterial();
                var derivedDecryptionKey = purpose.GetDerivedEncryptionKey(masterDecryptionKey).GetKeyMaterial();

                // Yield the IsolateApps keys
                yield return (derivedValidationKey, derivedDecryptionKey);
            }

            {
                var masterValidationKey = ModernKeyGenerator.GetValidationKey(autogenKeys, false, true, "", appId);
                var masterDecryptionKey = ModernKeyGenerator.GetEncryptionKey(autogenKeys, false, true, "", appId);

                var derivedValidationKey = purpose.GetDerivedValidationKey(masterValidationKey).GetKeyMaterial();
                var derivedDecryptionKey = purpose.GetDerivedEncryptionKey(masterDecryptionKey).GetKeyMaterial();

                // Yield the IsolateByAppId keys
                yield return (derivedValidationKey, derivedDecryptionKey);
            }

            {
                var masterValidationKey = ModernKeyGenerator.GetValidationKey(autogenKeys, true, true, "", appId);
                var masterDecryptionKey = ModernKeyGenerator.GetEncryptionKey(autogenKeys, true, true, "", appId);

                var derivedValidationKey = purpose.GetDerivedValidationKey(masterValidationKey).GetKeyMaterial();
                var derivedDecryptionKey = purpose.GetDerivedEncryptionKey(masterDecryptionKey).GetKeyMaterial();

                // Yield the IsolateApps & IsolateByAppId keys
                yield return (derivedValidationKey, derivedDecryptionKey);
            }

        }
    }

    static byte[] HexStringToBytes(string hex)
    {
        return Enumerable.Range(0, hex.Length / 2)
            .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
            .ToArray();
    }

}
