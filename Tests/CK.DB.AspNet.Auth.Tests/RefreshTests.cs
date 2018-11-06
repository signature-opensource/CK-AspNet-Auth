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
        public async Task refreshing_full_correctly_handles_impersonation_changes()
        {
            var user = TestHelper.StObjMap.StObjs.Obtain<UserTable>();
            var basic = TestHelper.StObjMap.StObjs.Obtain<IBasicAuthenticationProvider>();
            using( var ctx = new SqlStandardCallContext() )
            using( var server = new AuthServer( configureServices: services =>
                    {
                        // In Net461, the StObjMap is done on this /bin: ImpersonationForEverybodyService is automatically
                        // registered in the DI container.
                        // In NetCoreApp, the StObjMap comes from the DBWithPasswordAndGoogle: ImpersonationForEverybodyService
                        // is not automatically registered.
#if !NET461
                        services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
#endif
                    } ) )
            {
                int idAlbert = await SetupUser( ctx, "Albert", "pass", user, basic );
                int idPaula = await SetupUser( ctx, "Paula", "pass", user, basic );
                RefreshResponse refreshResponse;
                AuthResponse authResponse;

                authResponse = await LoginUserSuccess( server, idAlbert, "Albert", "pass" );

                var newAlbertName = Guid.NewGuid().ToString();
                await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );

                server.Client.Token = authResponse.Token;
                refreshResponse = await RefreshSuccess( server, true, AuthLevel.Normal );

                refreshResponse.Info.User.UserId.Should().Be( idAlbert );
                refreshResponse.Info.User.UserName.Should().Be( newAlbertName );

                server.Client.Token = refreshResponse.Token;
                authResponse = await Impersonate( server, idPaula, true );
                authResponse.Info.User.UserName.Should().Be( "Paula" );
                authResponse.Info.ActualUser.UserName.Should().Be( newAlbertName );

                server.Client.Token = authResponse.Token;
                refreshResponse = await RefreshSuccess( server, true, AuthLevel.Normal );
                refreshResponse.Info.Should().BeEquivalentTo( authResponse.Info, options => options.Excluding( info => info.Expires ) );

                server.Client.Token = refreshResponse.Token;
                newAlbertName = Guid.NewGuid().ToString();
                var newPaulaName = Guid.NewGuid().ToString();
                await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );
                await user.UserNameSetAsync( ctx, 1, idPaula, newPaulaName );
                refreshResponse = await RefreshSuccess( server, true, AuthLevel.Normal );
                refreshResponse.Info.User.UserName.Should().Be( newPaulaName );
                refreshResponse.Info.ActualUser.UserName.Should().Be( newAlbertName );

                server.Client.Token = refreshResponse.Token;
                await user.UserNameSetAsync( ctx, 1, idPaula, "Paula" );
                refreshResponse = await RefreshSuccess( server, true, AuthLevel.Normal );
                refreshResponse.Info.User.UserName.Should().Be( "Paula" );
                refreshResponse.Info.ActualUser.UserName.Should().Be( newAlbertName );

                server.Client.Token = refreshResponse.Token;
                await user.UserNameSetAsync( ctx, 1, idAlbert, "Albert" );
                authResponse = await Impersonate( server, idAlbert, false );
                authResponse.Info.User.UserId.Should().Be( idAlbert );
                authResponse.Info.User.UserName.Should().Be( newAlbertName,
                    "Impersonation in the ImpersonationForEverybodyService does not refresh the actual user." );

                server.Client.Token = authResponse.Token;
                refreshResponse = await RefreshSuccess( server, true, AuthLevel.Normal );
                refreshResponse.Info.ActualUser.UserName.Should().Be( "Albert" );
            }
        }

        static async Task<AuthResponse> Impersonate( AuthServer server, int idTarget, bool expectedImpersonated )
        {
            HttpResponseMessage m = await server.Client.PostJSON( impersonateUri, $@"{{ ""userId"": ""{idTarget}"" }}" );
            var r = AuthResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
            r.Info.IsImpersonated.Should().Be( expectedImpersonated );
            return r;
        }

        static async Task<RefreshResponse> RefreshSuccess( AuthServer server, bool full, AuthLevel expectedLevel )
        {
            HttpResponseMessage m = await server.Client.Get( full ? refreshUri + "?full" : refreshUri );
            var r = RefreshResponse.Parse( server.TypeSystem, await m.Content.ReadAsStringAsync() );
            r.Info.Level.Should().Be( expectedLevel );
            return r;
        }

        static async Task<AuthResponse> LoginUserSuccess( AuthServer server, int idAlbert, string userName, string password )
        {
            var payload = new JObject(
                                new JProperty( "userName", userName ),
                                new JProperty( "password", password ) );
            HttpResponseMessage authBasic = await server.Client.PostJSON( basicLoginUri, payload.ToString() );
            var c = AuthResponse.Parse( server.TypeSystem, await authBasic.Content.ReadAsStringAsync() );
            c.Info.Level.Should().Be( AuthLevel.Normal );
            c.Info.User.UserId.Should().Be( idAlbert );
            c.Token.Should().NotBeNullOrWhiteSpace();
            return c;
        }

        static async Task<int> SetupUser( SqlStandardCallContext ctx, string userName, string password, UserTable user, IBasicAuthenticationProvider basic )
        {
            int idUser = await user.CreateUserAsync( ctx, 1, userName );
            if( idUser == -1 ) idUser = await user.FindByNameAsync( ctx, userName );
            await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );
            return idUser;
        }
    }
}
