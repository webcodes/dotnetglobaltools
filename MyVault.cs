using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using McMaster.Extensions.CommandLineUtils;

namespace myvault
{
    [Command(Name="vault", Description = "Vault to store and retrieve secrets or to generate password"),
    Subcommand("generate-password", typeof(GeneratePassword)) 
    ,Subcommand("get",typeof(Get)),
    Subcommand("set",typeof(Set))]
    class MyVault
    {
        public static int Main(string[] args) => CommandLineApplication.Execute<MyVault>(args);
        private int OnExecute(CommandLineApplication application, IConsole console)
        {
            console.WriteLine("You must specify a subcommand");
            application.ShowHelp();
            return 1;
        }

        [Command("get", Description="Retrieve a stored secret by key"), HelpOption]
        private class Get
        {
            [Required]
            [Argument(0)]
            public string Key {get;}

            [Option]
            public string Password {get; set;}

            private void OnExecute(IConsole console)
            {
                if (string.IsNullOrEmpty(Password))
                {
                    Password = Prompt.GetPassword("Enter your password", promptColor: ConsoleColor.White,
                        promptBgColor: ConsoleColor.Cyan);
                }

                using (Aes myAes = Aes.Create())
                {
                    // https://stackoverflow.com/questions/4384035/cryptderivekey-fails-for-aes-algorithm-name
                    // Decrypt the bytes to a string.
                    byte[] salt = Encoding.Unicode.GetBytes("vaultsalt");
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Password, salt);
                    myAes.Key = rfc2898DeriveBytes.GetBytes(myAes.KeySize / 8);
                    myAes.IV =  rfc2898DeriveBytes.GetBytes(myAes.BlockSize / 8);

                    var encString = Environment.GetEnvironmentVariable($"vault_{Key}", EnvironmentVariableTarget.User);
                    var encrypted = Encoding.Unicode.GetBytes(encString);

                    string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                }
            }

            
        }
        
        [Command("set", Description="Store a stored secret by key"), HelpOption]
        private class Set
        {
            [Required]
            [Argument(0)]
            public string Key {get;}

            [Required]
            [Argument(1)]
            public string Value {get;}

            [Option]
            public string Password {get; set;}

            private void OnExecute(IConsole console)
            {
                if (string.IsNullOrEmpty(Password))
                {
                    
                    Password = Prompt.GetPassword("Enter your password", promptColor: ConsoleColor.White,
                        promptBgColor: ConsoleColor.DarkBlue);
                }
                using (Aes myAes = Aes.Create())
                {
                    byte[] salt = Encoding.Unicode.GetBytes("vaultsalt");
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(Password, salt);
                    myAes.Key = rfc2898DeriveBytes.GetBytes(myAes.KeySize / 8);
                    myAes.IV =  rfc2898DeriveBytes.GetBytes(myAes.BlockSize / 8);
                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes_Aes(Value, myAes.Key, myAes.IV);

                    Environment.SetEnvironmentVariable($"vault_{Key}", Encoding.Unicode.GetString(encrypted), EnvironmentVariableTarget.User);
                    // string roundtrip = DecryptStringFromBytes_Aes(_encrypted, myAes.Key, myAes.IV);
                    // Console.WriteLine("Round Trip: {0}", roundtrip);
                }
            }

            
        }

        [Command("generate-password", Description="Generate Password"), HelpOption]
        private class GeneratePassword
        {
            [Range(8, 32)]
            [Option]
            public int Length {get;} = 8;

            [DisallowedCharSet]
            [Option(Description="Exclude character group(s) in the password. [special upper digit]")]
            public List<string> Excludes {get;}

            private void OnExecute(IConsole console)
            {
                var password = GenerateRandomPassword();
                console.WriteLine($"Password generated is {password}");
            }

            private string GenerateRandomPassword()
            {
                var includeSpecial = Excludes == null || !Excludes.Contains("special");
                var includeUpper = Excludes == null || !Excludes.Contains("upper");
                var includeDigit = Excludes == null || !Excludes.Contains("digit");
                var allowedStringSb = new StringBuilder("abcdefghijklmnopqrstuvwxyz");
                if (includeUpper)
                {
                    allowedStringSb.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                }
                if(includeDigit)
                {
                    allowedStringSb.Append("1234567890");
                }
                if(includeSpecial)
                {
                    allowedStringSb.Append("!#$^&*");
                }

                char[] chars = new char[Length];
                Random rd = new Random();
                var allowedChars = allowedStringSb.ToString();
                for (int i = 0; i < Length; i++)
                {
                chars[i] = allowedChars[rd.Next(0, allowedChars.Length)];
                }

                return new string(chars);
            }
        }

        class DisallowedCharSetAttribute : ValidationAttribute
        {
            protected override ValidationResult IsValid(object value, ValidationContext validationContext)
            {
                if (value == null || (value is string str && str != "special" && str != "upper" && str != "digit"))
                {
                    return new ValidationResult(FormatErrorMessage(validationContext.DisplayName));
                }
                return ValidationResult.Success;
            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
            {
                // Check arguments.
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                byte[] encrypted;
                
                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }


                // Return the encrypted bytes from the memory stream.
                return encrypted;

            }

            static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
            {
                // Check arguments.
                if (cipherText == null || cipherText.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                // Create an Aes object
                // with the specified key and IV.
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {

                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                }
                return plaintext;
            }
    }
}
