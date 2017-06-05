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

namespace WebApp.Tests
{
    [TestFixture]
    public class ExternalAuthenticationTests
    {
        TestClient _client;

        [SetUp]
        public void Initialize() => _client = WebAppHelper.GetRunningTestClient();

        [Test]
        public void start_login_on_webfront()
        {
            HttpResponseMessage m = _client.Get( WebAppUrl.StartLoginUri + "?provider=oidc" );
            m.EnsureSuccessStatusCode();
            HttpResponseMessage consentScreenOrAccepted = AnswerLoginForm( m, "bob", "password", true );
            HttpResponseMessage accepted = AnswerConsentForm( consentScreenOrAccepted, true );
            HttpResponseMessage final = PostAcceptedResult( accepted );
        }
        HttpResponseMessage AnswerLoginForm( HttpResponseMessage m, string name, string password, bool rememberLogin )
        {
            string content = m.Content.ReadAsStringAsync().Result;
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
            return _client.Post( new Uri( idServerUri, form.Action ), formValues );
        }

        class ConsentInput
        {
            public string Name { get; set; }

            public bool Required { get; set; }

            public bool Checked { get; set; }
        }

        HttpResponseMessage AnswerConsentForm( HttpResponseMessage m, bool rememberConsent )
        {
            var idServerUri = m.RequestMessage.RequestUri;
            string content = m.Content.ReadAsStringAsync().Result;
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
            return _client.Post( new Uri( idServerUri, form.Action ), formValues );
        }

        HttpResponseMessage PostAcceptedResult( HttpResponseMessage m )
        {
            var content = m.Content.ReadAsStringAsync().Result;
            content.Should().EndWith( "<script>(function(){document.forms[0].submit();})();</script>" );
            var doc = new HtmlParser().Parse( content );
            var form = doc.Forms[0];
            var values = form.Elements.OfType<IHtmlInputElement>()
                            .Select( e => new KeyValuePair<string, string>( e.Name, e.Value ) );
            return _client.Post( form.Action, values );
        }

    }
}
