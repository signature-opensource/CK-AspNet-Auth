using CK.DB.Actor;
using CK.DB.Auth;
using CK.Core;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static CK.Testing.DBSetupTestHelper;
using CK.SqlServer;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using FluentAssertions;
using CK.Auth;
using CK.AspNet.Auth;
using Microsoft.Extensions.DependencyInjection;

namespace CK.DB.AspNet.Auth.Tests
{
    [TestFixture]
    public class RefreshTests
    {
        const string basicLoginUri = "/.webfront/c/basicLogin";
        const string refreshUri = "/.webfront/c/refresh";
        const string impersonateUri = "/.webfront/c/impersonate";

        [Test]
        public async Task refreshing_with_callBackend_correctly_handles_impersonation_changes_Async()
        {
            var user = TestHelper.StObjMap.StObjs.Obtain<UserTable>();
            var basic = TestHelper.StObjMap.StObjs.Obtain<IBasicAuthenticationProvider>();
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer( s => s.AddSingleton<IWebFrontAuthImpersonationService,ImpersonationForEverybodyService>() ) )
            {
                int idAlbert = await SetupUserAsync( ctx, "Albert", "pass", user, basic );
                int idPaula = await SetupUserAsync( ctx, "Paula", "pass", user, basic );
                RefreshResponse refreshResponse;
                AuthResponse authResponse;

                authResponse = await LoginUserSuccessAsync( server, idAlbert, "Albert", "pass" );

                var newAlbertName = Guid.NewGuid().ToString();
                await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );

                server.Client.Token = authResponse.Token;
                refreshResponse = await RefreshSuccessAsync( server, true, AuthLevel.Normal );

                refreshResponse.Info.User.UserId.Should().Be( idAlbert );
                refreshResponse.Info.User.UserName.Should().Be( newAlbertName );

                server.Client.Token = refreshResponse.Token;
                authResponse = await ImpersonateAsync( server, idPaula, true );
                authResponse.Info.User.UserName.Should().Be( "Paula" );
                authResponse.Info.ActualUser.UserName.Should().Be( newAlbertName );

                server.Client.Token = authResponse.Token;
                refreshResponse = await RefreshSuccessAsync( server, true, AuthLevel.Normal );
                refreshResponse.Info.Should().BeEquivalentTo( authResponse.Info, options => options.Excluding( info => info.Expires ) );

                server.Client.Token = refreshResponse.Token;
                newAlbertName = Guid.NewGuid().ToString();
                var newPaulaName = Guid.NewGuid().ToString();
                await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );
                await user.UserNameSetAsync( ctx, 1, idPaula, newPaulaName );
                refreshResponse = await RefreshSuccessAsync( server, true, AuthLevel.Normal );
                refreshResponse.Info.User.UserName.Should().Be( newPaulaName );
                refreshResponse.Info.ActualUser.UserName.Should().Be( newAlbertName );

                server.Client.Token = refreshResponse.Token;
                await user.UserNameSetAsync( ctx, 1, idPaula, "Paula" );
                refreshResponse = await RefreshSuccessAsync( server, true, AuthLevel.Normal );
                refreshResponse.Info.User.UserName.Should().Be( "Paula" );
                refreshResponse.Info.ActualUser.UserName.Should().Be( newAlbertName );

                server.Client.Token = refreshResponse.Token;
                await user.UserNameSetAsync( ctx, 1, idAlbert, "Albert" );
                authResponse = await ImpersonateAsync( server, idAlbert, false );
                authResponse.Info.User.UserId.Should().Be( idAlbert );
                authResponse.Info.User.UserName.Should().Be( newAlbertName,
                    "Impersonation in the ImpersonationForEverybodyService does not refresh the actual user." );

                server.Client.Token = authResponse.Token;
                refreshResponse = await RefreshSuccessAsync( server, true, AuthLevel.Normal );
                refreshResponse.Info.ActualUser.UserName.Should().Be( "Albert" );
            }
        }

        static async Task<AuthResponse> ImpersonateAsync( AuthServer server, int idTarget, bool expectedImpersonated )
        {
            HttpResponseMessage m = await server.Client.PostJSONAsync( impersonateUri, $@"{{ ""userId"": ""{idTarget}"" }}" );
            var r = AuthResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
            r.Info.IsImpersonated.Should().Be( expectedImpersonated );
            return r;
        }

        static async Task<RefreshResponse> RefreshSuccessAsync( AuthServer server, bool callBackend, AuthLevel expectedLevel )
        {
            HttpResponseMessage m = await server.Client.GetAsync( callBackend ? refreshUri + "?callBackend" : refreshUri );
            var r = RefreshResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
            r.Info.Level.Should().Be( expectedLevel );
            return r;
        }

        static async Task<AuthResponse> LoginUserSuccessAsync( AuthServer server, int idAlbert, string userName, string password )
        {
            var payload = new JObject(
                                new JProperty( "userName", userName ),
                                new JProperty( "password", password ) );
            HttpResponseMessage authBasic = await server.Client.PostJSONAsync( basicLoginUri, payload.ToString() );
            var c = AuthResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
            c.Info.Level.Should().Be( AuthLevel.Normal );
            c.Info.User.UserId.Should().Be( idAlbert );
            c.Token.Should().NotBeNullOrWhiteSpace();
            return c;
        }

        static async Task<int> SetupUserAsync( SqlStandardCallContext ctx, string userName, string password, UserTable user, IBasicAuthenticationProvider basic )
        {
            int idUser = await user.CreateUserAsync( ctx, 1, userName );
            if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
            await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );
            return idUser;
        }
    }
}
