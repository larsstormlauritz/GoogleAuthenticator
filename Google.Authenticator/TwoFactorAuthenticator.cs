using QRCoder;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Google.Authenticator
{
    /// <summary>
    /// modified from
    /// http://brandonpotter.com/2014/09/07/implementing-free-two-factor-authentication-in-net-using-google-authenticator/
    /// https://github.com/brandonpotter/GoogleAuthenticator
    /// With elements borrowed from https://github.com/stephenlawuk/GoogleAuthenticator
    /// </summary>
    public class TwoFactorAuthenticator
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private TimeSpan DefaultClockDriftTolerance { get; }

        public TwoFactorAuthenticator()
        {
            DefaultClockDriftTolerance = TimeSpan.FromMinutes(5);
        }

        /// <summary>
        /// Generate a setup code for a Google Authenticator user to scan
        /// </summary>
        /// <param name="issuer">Issuer ID (the name of the system, i.e. 'MyApp'), can be omitted but not recommended https://github.com/google/google-authenticator/wiki/Key-Uri-Format </param>
        /// <param name="accountTitleNoSpaces">Account Title (no spaces)</param>
        /// <param name="accountSecretKey">Account Secret Key</param>
        /// <param name="secretIsBase32">Flag saying if accountSecretKey is in Base32 format or original secret</param>
        /// <param name="qrPixelsPerModule">Number of pixels per QR Module (2 pixels give ~ 100x100px QRCode)</param>
        /// <returns>SetupCode object</returns>
        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, bool secretIsBase32, int qrPixelsPerModule)
        {
            var key = secretIsBase32 ? Base32Encoding.ToBytes(accountSecretKey) : Encoding.UTF8.GetBytes(accountSecretKey);
            return GenerateSetupCode(issuer, accountTitleNoSpaces, key, qrPixelsPerModule);
        }

        /// <summary>
        /// Generate a setup code for a Google Authenticator user to scan
        /// </summary>
        /// <param name="issuer">Issuer ID (the name of the system, i.e. 'MyApp'), can be omitted but not recommended https://github.com/google/google-authenticator/wiki/Key-Uri-Format </param>
        /// <param name="accountTitleNoSpaces">Account Title (no spaces)</param>
        /// <param name="accountSecretKey">Account Secret Key as byte[]</param>
        /// <param name="qrPixelsPerModule">Number of pixels per QR Module (2 = ~120x120px QRCode)</param>
        /// <param name="generateQrCode"></param>
        /// <returns>SetupCode object</returns>
        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, byte[] accountSecretKey, int qrPixelsPerModule, bool generateQrCode = true)
        {
            if (string.IsNullOrWhiteSpace(accountTitleNoSpaces)) { throw new NullReferenceException("Account Title is null"); }
            accountTitleNoSpaces = RemoveWhitespace(Uri.EscapeUriString(accountTitleNoSpaces));
            var encodedSecretKey = Base32Encoding.ToString(accountSecretKey);
            var provisionUrl = string.IsNullOrWhiteSpace(issuer) ? 
                $"otpauth://totp/{accountTitleNoSpaces}?secret={encodedSecretKey.Trim('=')}" : 
                $"otpauth://totp/{UrlEncode(issuer)}:{accountTitleNoSpaces}?secret={encodedSecretKey.Trim('=')}&issuer={UrlEncode(issuer)}";

            var qrCodeUrl = string.Empty;
            if (!generateQrCode) return new SetupCode(accountTitleNoSpaces, encodedSecretKey.Trim('='), qrCodeUrl);

            using (var qrGenerator = new QRCodeGenerator())
            using (var qrCodeData = qrGenerator.CreateQrCode(provisionUrl, QRCodeGenerator.ECCLevel.Q))
            using (var qrCode = new QRCode(qrCodeData))
            using (var qrCodeImage = qrCode.GetGraphic(qrPixelsPerModule))
            using (var ms = new MemoryStream())
            {
                qrCodeImage.Save(ms, System.Drawing.Imaging.ImageFormat.Png);

                qrCodeUrl = $"data:image/png;base64,{Convert.ToBase64String(ms.ToArray())}";
            }

            return new SetupCode(accountTitleNoSpaces, encodedSecretKey.Trim('='), qrCodeUrl);
        }

        private static string RemoveWhitespace(string str)
        {
            return new string(str.Where(c => !char.IsWhiteSpace(c)).ToArray());
        }

        private string UrlEncode(string value)
        {
            var result = new StringBuilder();
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            foreach (var symbol in value)
            {
                if (validChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + $"{(int) symbol:X2}");
                }
            }

            return result.ToString().Replace(" ", "%20");
        }

        public string GeneratePinAtInterval(string accountSecretKey, long counter, int digits = 6)
        {
            return GenerateHashedCode(accountSecretKey, counter, digits);
        }

        internal string GenerateHashedCode(string secret, long iterationNumber, int digits = 6)
        {
            var key = Encoding.UTF8.GetBytes(secret);
            return GenerateHashedCode(key, iterationNumber, digits);
        }

        internal string GenerateHashedCode(byte[] key, long iterationNumber, int digits = 6)
        {
            var counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counter);
            }

            var hmac = new HMACSHA1(key);
                        
            var hash = hmac.ComputeHash(counter);

            var offset = hash[hash.Length - 1] & 0xf;

            // Convert the 4 bytes into an integer, ignoring the sign.
            var binary =
                ((hash[offset] & 0x7f) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | hash[offset + 3];

            var password = binary % (int)Math.Pow(10, digits);
            return password.ToString(new string('0', digits));
        }

        private long GetCurrentCounter()
        {
            return GetCurrentCounter(DateTime.UtcNow, Epoch, 30);
        }

        private long GetCurrentCounter(DateTime now, DateTime epoch, int timeStep)
        {
            return (long)(now - epoch).TotalSeconds / timeStep;
        }
                
        public bool ValidateTwoFactorPin(string accountSecretKey, string twoFactorCodeFromClient)
        {
            return ValidateTwoFactorPin(accountSecretKey, twoFactorCodeFromClient, DefaultClockDriftTolerance);
        }

        public bool ValidateTwoFactorPin(string accountSecretKey, string twoFactorCodeFromClient, TimeSpan timeTolerance)
        {
            var codes = GetCurrentPins(accountSecretKey, timeTolerance);
            return codes.Any(c => c == twoFactorCodeFromClient);
        }

        public string GetCurrentPin(string accountSecretKey)
        {
            return GeneratePinAtInterval(accountSecretKey, GetCurrentCounter());
        }
        
         public string GetCurrentPin(string accountSecretKey,DateTime now)
        {
            return GeneratePinAtInterval(accountSecretKey, GetCurrentCounter(now,Epoch,30));
        }

        public string[] GetCurrentPins(string accountSecretKey)
        {
            return GetCurrentPins(accountSecretKey, DefaultClockDriftTolerance);
        }

        public string[] GetCurrentPins(string accountSecretKey, TimeSpan timeTolerance)
        {
            var codes = new List<string>();
            var iterationCounter = GetCurrentCounter();
            var iterationOffset = 0;

            if (timeTolerance.TotalSeconds > 30)
            {
                iterationOffset = Convert.ToInt32(timeTolerance.TotalSeconds / 30.00);
            }

            var iterationStart = iterationCounter - iterationOffset;
            var iterationEnd = iterationCounter + iterationOffset;

            for (var counter = iterationStart; counter <= iterationEnd; counter++)
            {
                codes.Add(GeneratePinAtInterval(accountSecretKey, counter));
            }

            return codes.ToArray();
        }
    }
}
