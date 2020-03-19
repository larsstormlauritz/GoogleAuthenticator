﻿using Xunit;
using Shouldly;

namespace Google.Authenticator.Tests
{
    public class AuthCodeTest
    {
        [Fact]
        public void BasicAuthCodeTest()
        {
            var secretKey = "PJWUMZKAUUFQKJBAMD6VGJ6RULFVW4ZH";
            var expected = "551508";

            var tfa = new TwoFactorAuthenticator();
            
            long currentTime = 1416643820;

            // I actually think you are supposed to divide the time by 30 seconds? Maybe need an overload that takes a DateTime?
            var actual = tfa.GeneratePinAtInterval(secretKey, currentTime, 6);

            actual.ShouldBe(expected);   
        }
    }
}
