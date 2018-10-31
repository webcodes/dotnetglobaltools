using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;
using McMaster.Extensions.CommandLineUtils;

namespace myvault
{
    [Command(Name="vault", Description = "Vault to store and retrieve secrets or to generate password"),
    Subcommand("generate-password", typeof(GeneratePassword)) 
    /*,Subcommand("get",typeof(Get)),
    Subcommand("set",typeof(Set))*/]
    class MyVault
    {
        public static int Main(string[] args) => CommandLineApplication.Execute<MyVault>(args);
        private int OnExecute(CommandLineApplication application, IConsole console)
        {
            console.WriteLine("You must specify a subcommand");
            application.ShowHelp();
            return 1;
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
    }
}
