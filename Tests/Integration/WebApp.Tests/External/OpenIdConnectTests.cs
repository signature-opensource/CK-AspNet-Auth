using AngleSharp;
using AngleSharp.Dom.Html;
using AngleSharp.Network.Default;
using AngleSharp.Parser.Html;
using CK.Auth;
using FluentAssertions;
using Newtonsoft.Json.Linq;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using CK.Text;
using Microsoft.AspNetCore.Http;
using System.Threading;
using CK.AspNet.Tester;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    [TestFixture]
    public class OpenIdConnectTests
    {
        TestClient _client;

        [SetUp]
        public void Initialize()
        {
            _client = WebAppHelper.GetRunningTestClient().GetAwaiter().GetResult();
            _client.ClearCookies( ".webfront/c" );
            _client.Token = null;
        }

        [Test]
        public async Task Bob_login_on_webfront_returns_User_NoAutoRegistration()
        {
            DBSetup.BobSetup();
            HttpResponseMessage m = await _client.Get( WebAppUrl.StartLoginUri + "?scheme=oidc" );
            m.EnsureSuccessStatusCode();
            HttpResponseMessage consentScreenOrAccepted = await AnswerLoginForm( m, "bob", "password", true );
            HttpResponseMessage accepted = await AnswerConsentForm( consentScreenOrAccepted, true );
            HttpResponseMessage finalErrorOrRedirect = await PostAcceptedResult( accepted );
            Tuple<HttpResponseMessage, string> final = await HandleFinalErrorOrRedirect( finalErrorOrRedirect );
            final.Item2.Should().Be( "User.NoAutoRegistration" );
        }

        [TestCase( true )]
        [TestCase( false )]
        public async Task Alice_login_when_Basic_logged_on_webfront_returns_Account_NoAutoBinding( bool useTokenInsteadOfRelyingOnCookies )
        {
            DBSetup.AliceSetup();
            LoginResponse r = await BasicAuthenticationTests.BasicLogin( _client, "alice", "password" );
            if( useTokenInsteadOfRelyingOnCookies ) _client.Token = r.Token;
            HttpResponseMessage m = await _client.Get( WebAppUrl.StartLoginUri + "?scheme=oidc" );
            m.EnsureSuccessStatusCode();
            HttpResponseMessage consentScreenOrAccepted = await AnswerLoginForm( m, "alice", "password", true );
            HttpResponseMessage accepted = await AnswerConsentForm( consentScreenOrAccepted, true );
            HttpResponseMessage finalErrorOrRedirect = await PostAcceptedResult( accepted );
            Tuple<HttpResponseMessage, string> final = await HandleFinalErrorOrRedirect( finalErrorOrRedirect );
            final.Item2.Should().Be( "Account.NoAutoBinding" );
        }

        [TestCase( null )]
        [TestCase( "&A=3&A=p&Other=param&X" )]
        public async Task Carol_login_on_webfront_succeeds( string userData )
        {
            DBSetup.CarolSetup();
            HttpResponseMessage m = await _client.Get( WebAppUrl.StartLoginUri + "?scheme=oidc" + userData );
            m.EnsureSuccessStatusCode();
            HttpResponseMessage consentScreenOrAccepted = await AnswerLoginForm( m, "carol", "password", true );
            HttpResponseMessage accepted = await AnswerConsentForm( consentScreenOrAccepted, true );
            HttpResponseMessage finalErrorOrRedirect = await PostAcceptedResult( accepted );
            Tuple<HttpResponseMessage, string> final = await HandleFinalErrorOrRedirect( finalErrorOrRedirect );
            final.Item2.Should().BeNull();
            string content = await final.Item1.Content.ReadAsStringAsync();
            content.Should().Contain( "window.opener.postMessage" );
            if( userData != null )
            {
                content.Should().Contain( @"""userData"":{""A"":[""3"",""p""],""Other"":""param"",""X"":""""}" );
            }
            else
            {
                content.Should().Contain( @"""userData"":{}" );
            }
            await CheckUserIsLoggedIn( "carol" );
        }

        [Test]
        public async Task login_works_also_with_Post()
        {
            DBSetup.CarolSetup();

            var userData = new List<KeyValuePair<string, string>>();
            userData.Add( new KeyValuePair<string, string>( "A", "3" ) );
            userData.Add( new KeyValuePair<string, string>( "A", "p" ) );
            userData.Add( new KeyValuePair<string, string>( "Other", "param" ) );
            userData.Add( new KeyValuePair<string, string>( "X", "" ) );

            HttpResponseMessage m = await _client.Post( WebAppUrl.StartLoginUri + "?scheme=oidc", userData );
            m.EnsureSuccessStatusCode();
            HttpResponseMessage consentScreenOrAccepted = await AnswerLoginForm( m, "carol", "password", true );
            HttpResponseMessage accepted = await AnswerConsentForm( consentScreenOrAccepted, true );
            HttpResponseMessage finalErrorOrRedirect = await PostAcceptedResult( accepted );
            Tuple<HttpResponseMessage, string> final = await HandleFinalErrorOrRedirect( finalErrorOrRedirect );
            final.Item2.Should().BeNull();
            string content = await final.Item1.Content.ReadAsStringAsync();
            content.Should().Contain( "window.opener.postMessage" );
            content.Should().Contain( @"""userData"":{""A"":[""3"",""p""],""Other"":""param"",""X"":""""}" );
            await CheckUserIsLoggedIn( "carol" );
        }

        [Test]
        public async Task login_with_return_url()
        {
            DBSetup.CarolSetup();

            HttpResponseMessage m = await _client.Get( WebAppUrl.StartLoginUri + "?scheme=oidc&returnUrl=/auth-done?p=67" );
            m.EnsureSuccessStatusCode();
            HttpResponseMessage consentScreenOrAccepted = await AnswerLoginForm( m, "carol", "password", true );
            HttpResponseMessage accepted = await AnswerConsentForm( consentScreenOrAccepted, true );
            HttpResponseMessage finalErrorOrRedirect = await PostAcceptedResult( accepted );
            Tuple<HttpResponseMessage, string> final = await HandleFinalErrorOrRedirect( finalErrorOrRedirect );
            final.Item2.Should().BeNull();
            string content = await final.Item1.Content.ReadAsStringAsync();
            content.Should().Contain( "window.url='http://localhost:4324/auth-done?p=67';" );
            await CheckUserIsLoggedIn( "carol" );
        }

        async Task CheckUserIsLoggedIn( string userName )
        {
            string json = await (await _client.Get( WebAppUrl.RefreshUri )).Content.ReadAsStringAsync();
            RefreshResponse r = RefreshResponse.Parse( WebAppHelper.AuthTypeSystem, json );
            _client.Token = r.Token;
            HttpResponseMessage auth = await _client.Get( WebAppUrl.TokenExplainUri );
            auth.Content.ReadAsStringAsync().Result.Should().Contain( userName );
        }

        async Task<HttpResponseMessage> AnswerLoginForm( HttpResponseMessage m, string name, string password, bool rememberLogin )
        {
            string content = await m.Content.ReadAsStringAsync();
            if( content.EndsWith( "<script>(function(){document.forms[0].submit();})();</script>" ) )
            {
                return m;
            }
            var idServerUri = m.RequestMessage.RequestUri;
            var doc = new HtmlParser().Parse( content );
            var form = doc.Forms[0];
            var formValues = new Dictionary<string, string>()
            {
                { "ReturnUrl", ((IHtmlInputElement)form["ReturnUrl"]).Value },
                { "__RequestVerificationToken", ((IHtmlInputElement)form["__RequestVerificationToken"]).Value },
                { "Password", password },
                { "UserName", name },
                { "RememberLogin", rememberLogin ? "true" : "false" }
            };
            return await _client.Post( new Uri( idServerUri, form.Action ), formValues );
        }

        class ConsentInput
        {
            public string Name { get; set; }

            public bool Required { get; set; }

            public bool Checked { get; set; }
        }

        async Task<HttpResponseMessage> AnswerConsentForm( HttpResponseMessage m, bool rememberConsent )
        {
            var idServerUri = m.RequestMessage.RequestUri;
            string content = await m.Content.ReadAsStringAsync();
            if( content.EndsWith( "<script>(function(){document.forms[0].submit();})();</script>" ) )
            {
                return m;
            }
            var doc = new HtmlParser().Parse( m.Content.ReadAsStringAsync().Result );
            var form = doc.Forms[0];
            var scopes = form.Elements.OfType<IHtmlInputElement>()
                            .Where( e => e.Name == "ScopesConsented" && e.Type == "checkbox" )
                            .Select( e => new ConsentInput()
                            {
                                Name = e.Value,
                                Checked = e.IsChecked,
                                Required = e.IsDisabled
                            } );

            var formValues = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>( "ReturnUrl", ((IHtmlInputElement)form["ReturnUrl"]).Value ),
                new KeyValuePair<string, string>( "__RequestVerificationToken", ((IHtmlInputElement)form["__RequestVerificationToken"]).Value ),
                new KeyValuePair<string, string>( "RememberConsent", rememberConsent ? "true" : "false" ),
                new KeyValuePair<string, string>( "button", "yes" )
            };
            foreach( var s in scopes.Where( e => e.Checked ).Select( e => e.Name ) )
            {
                formValues.Add( new KeyValuePair<string, string>( "ScopesConsented", s ) );
            }
            return await _client.Post( new Uri( idServerUri, form.Action ), formValues );
        }

        Task<HttpResponseMessage> PostAcceptedResult( HttpResponseMessage m )
        {
            var content = m.Content.ReadAsStringAsync().Result;
            content.Should().EndWith( "<script>(function(){document.forms[0].submit();})();</script>" );
            var doc = new HtmlParser().Parse( content );
            var form = doc.Forms[0];
            var values = form.Elements.OfType<IHtmlInputElement>()
                            .Select( e => new KeyValuePair<string, string>( e.Name, e.Value ) );
            return _client.Post( form.Action, values );
        }

        async Task<Tuple<HttpResponseMessage, string>> HandleFinalErrorOrRedirect( HttpResponseMessage m )
        {
            var content = await m.Content.ReadAsStringAsync();
            const string errorMark = "{\"errorId\":\"";
            int idxError = content.IndexOf( errorMark );
            if( idxError > 0 )
            {
                return Tuple.Create( (HttpResponseMessage)null, content.Substring( idxError + errorMark.Length ).Split( '"' )[0] );
            }
            return Tuple.Create( m, (string)null );
        }


    }
}
