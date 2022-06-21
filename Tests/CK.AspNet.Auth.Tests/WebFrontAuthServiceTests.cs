using CK.AspNet.Tester;
using CK.Auth;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using CK.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;

namespace CK.AspNet.Auth.Tests
{
    [TestFixture]
    public class WebFrontAuthServiceTests
    {
        /// <summary>
        /// Calling ChallengeAsync leads to WebFrontAuthService.HanddleAutheticate that sets HttpContext.User principal
        /// from the current IAutheticationInfo.
        /// </summary>
        [Test]
        public async Task calling_challenge_Async()
        {
            using( var s = new AuthServer() )
            {
                // Login: the 2 cookies are set on .webFront/c/ path.
                var login = await s.LoginAlbertViaBasicProviderAsync();
                Debug.Assert( login.Info != null );
                await s.Client.GetAsync( "/CallChallengeAsync" );
            }
        }
    }
}
