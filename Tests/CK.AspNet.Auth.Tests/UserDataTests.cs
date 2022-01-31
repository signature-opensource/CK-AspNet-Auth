using CK.Core;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
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
            using( var s = new AuthServer( configureServices: services =>
            {
                if( useGenericWrapper )
                {
                    services.AddSingleton<IWebFrontAuthUnsafeDirectLoginAllowService, BasicDirectLoginAllower>();
                }
            } ) )
            {
                var expectation = new Dictionary<string, string?>();

                {
                    expectation.Add( "d", "a" );
                    var r = await s.LoginViaBasicProviderAsync( "Albert", useGenericWrapper: useGenericWrapper, jsonUserData: @"{""d"":""a""}" );
                    r.UserData.Should().BeEquivalentTo( expectation );
                }
                {
                    expectation.Add( "e", "b" );
                    var r = await s.LoginViaBasicProviderAsync( "Albert", useGenericWrapper: useGenericWrapper, jsonUserData: @"{""d"":""a"",""e"":""b""}" );
                    r.UserData.Should().BeEquivalentTo( expectation );
                }
                {
                    expectation.Add( "f", null );
                    expectation.Add( "g", String.Empty );
                    var r = await s.LoginViaBasicProviderAsync( "Albert", useGenericWrapper: useGenericWrapper, jsonUserData: @"{""d"":""a"",""e"":""b"",""f"":null,""g"":""""}" );
                    r.UserData.Should().BeEquivalentTo( expectation );
                }
            }
        }

    }
}
