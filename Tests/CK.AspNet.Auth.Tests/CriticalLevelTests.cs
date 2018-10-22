using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CK.Auth;
using FluentAssertions;
using NUnit.Framework;

namespace CK.AspNet.Auth.Tests
{
    [TestFixture]
    public class CriticalLevelTests
    {
        [Test]
        public async Task when_no_dictionary_is_set_returns_normal()
        {
            using( var s = new AuthServer( options => options.ExpireTimeSpan = TimeSpan.FromHours( 1 ) ) )
            {
                var r = await s.Client.PostJSON( AuthServer.BasicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                r.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, r.Content.ReadAsStringAsync().Result );
                c.Info.Level.Should().Be( AuthLevel.Normal );
                c.Info.Expires.Should().BeCloseTo( DateTime.UtcNow + TimeSpan.FromHours( 1 ), 60_000 );
                c.Info.CriticalExpires.HasValue.Should().BeFalse();
            }
        }

        [Test]
        public async Task when_dictionary_has_no_matching_key_returns_normal()
        {
            var scts = new Dictionary<string, TimeSpan> { { "SomeScheme", TimeSpan.FromHours( 1 ) } };

            void SetOptions( WebFrontAuthOptions options )
            {
                options.ExpireTimeSpan = TimeSpan.FromHours( 1 );
                options.SchemesCriticalTimeSpan = scts;
            }

            using( var s = new AuthServer( SetOptions ) )
            {
                var r = await s.Client.PostJSON( AuthServer.BasicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                r.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, r.Content.ReadAsStringAsync().Result );
                c.Info.Level.Should().Be( AuthLevel.Normal );
                c.Info.Expires.Should().BeCloseTo( DateTime.UtcNow + TimeSpan.FromHours( 1 ), 60_000 );
                c.Info.CriticalExpires.HasValue.Should().BeFalse();
            }
        }

        [Test]
        public async Task when_dictionary_has_matching_key_with_valid_value_returns_critical()
        {
            var scts = new Dictionary<string, TimeSpan> { { "Basic", TimeSpan.FromHours( 1 ) } };
            void SetOptions( WebFrontAuthOptions options )
            {
                options.ExpireTimeSpan = TimeSpan.FromHours( 2 );
                options.SchemesCriticalTimeSpan = scts;
            }

            using( var s = new AuthServer( SetOptions ) )
            {
                var r = await s.Client.PostJSON( AuthServer.BasicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                r.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, r.Content.ReadAsStringAsync().Result );
                c.Info.Level.Should().Be( AuthLevel.Critical );
                c.Info.Expires.Should().BeCloseTo( DateTime.UtcNow + TimeSpan.FromHours( 2 ), 60_000 );
                c.Info.CriticalExpires.Should().BeCloseTo( DateTime.UtcNow + TimeSpan.FromHours( 1 ), 60_000 );
            }
        }

        [Test]
        public async Task when_dictionary_has_matching_key_with_invalid_value_returns_normal()
        {
            var scts = new Dictionary<string, TimeSpan> { { "Basic", TimeSpan.FromHours( -1 ) } };

            void SetOptions( WebFrontAuthOptions options )
            {
                options.ExpireTimeSpan = TimeSpan.FromHours( 1 );
                options.SchemesCriticalTimeSpan = scts;
            }

            using( var s = new AuthServer( SetOptions ) )
            {
                var r = await s.Client.PostJSON( AuthServer.BasicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                r.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, r.Content.ReadAsStringAsync().Result );
                c.Info.Level.Should().Be( AuthLevel.Normal );
                c.Info.Expires.Should().BeCloseTo( DateTime.UtcNow + TimeSpan.FromHours( 1 ), 60_000 );
                c.Info.CriticalExpires.HasValue.Should().BeFalse();
            }
        }

        [Test]
        public async Task when_expires_is_shorter_than_critical_expires_then_expires_is_extended()
        {
            var scts = new Dictionary<string, TimeSpan> { { "Basic", TimeSpan.FromHours( 2 ) } };

            void SetOptions( WebFrontAuthOptions options )
            {
                options.ExpireTimeSpan = TimeSpan.FromHours( 1 );
                options.SchemesCriticalTimeSpan = scts;
            }

            using( var s = new AuthServer( SetOptions ) )
            {
                var r = await s.Client.PostJSON( AuthServer.BasicLoginUri, "{\"userName\":\"Albert\",\"password\":\"success\"}" );
                r.EnsureSuccessStatusCode();
                var c = RefreshResponse.Parse( s.TypeSystem, r.Content.ReadAsStringAsync().Result );
                c.Info.Level.Should().Be( AuthLevel.Critical );
                c.Info.Expires.Should().BeCloseTo( DateTime.UtcNow + TimeSpan.FromHours( 2 ), 60_000 );
                c.Info.CriticalExpires.Should().BeCloseTo( DateTime.UtcNow + TimeSpan.FromHours( 2 ), 60_000 );
            }
        }
    }
}
