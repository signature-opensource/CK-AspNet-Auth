using CK.Core;
using CK.Testing;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.AspNet.Auth.Tests
{
    [TestFixture]
    public class UserDataTests
    {
        class BasicDirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
        {
            public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
            {
                return Task.FromResult( scheme == "Basic" );
            }
        }


        [TestCase( true )]
        [TestCase( false )]
        public async Task basic_login_userData_Async( bool useGenericWrapper )
        {
            await using var runningServer = await LocalHelper.CreateLocalAuthServerAsync( services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            } );

            var expectation = new List<(string, string?)>();
            {
                expectation.Add( ("d", "a") );
                var r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper, jsonUserData: @"{""d"":""a""}" );
                r.UserData.Should().BeEquivalentTo( expectation );
            }
            {
                expectation.Add( ("e", "b") );
                var r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper, jsonUserData: @"{""d"":""a"",""e"":""b""}" );
                r.UserData.Should().BeEquivalentTo( expectation );
            }
            {
                expectation.Add( ("f", null) );
                expectation.Add( ("g", String.Empty) );
                var r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, useGenericWrapper: useGenericWrapper, jsonUserData: @"{""d"":""a"",""e"":""b"",""f"":null,""g"":""""}" );
                r.UserData.Should().BeEquivalentTo( expectation );
            }
        }

    }
}
