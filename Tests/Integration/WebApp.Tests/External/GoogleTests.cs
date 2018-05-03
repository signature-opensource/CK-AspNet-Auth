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
using CK.AspNet.Tester;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    [TestFixture]
    public class GoogleTests
    {
        TestClient _client;

        //[SetUp]
        public void Initialize() => _client = WebAppHelper.GetRunningTestClient().GetAwaiter().GetResult();

        //[Test]
        public async Task start_login_on_webfront()
        {
            HttpResponseMessage m = await _client.Get( WebAppUrl.StartLoginUri + "?scheme=Google" );
            m.EnsureSuccessStatusCode();
            HttpResponseMessage consentScreenOrAccepted = AnswerLoginForm( m, "ojdhfziifofdhsjs@gmail.com", "2enoNiARdF1Y1LdziC9w", false );
            HttpResponseMessage accepted = AnswerConsentForm( consentScreenOrAccepted, true );
            HttpResponseMessage final = PostAcceptedResult( accepted );
        }

        HttpResponseMessage AnswerLoginForm( HttpResponseMessage m, string name, string password, bool rememberLogin )
        {
            throw new NotImplementedException( "Webscraping needs JS support." );
        }

        class ConsentInput
        {
            public string Name { get; set; }

            public bool Required { get; set; }

            public bool Checked { get; set; }
        }

        HttpResponseMessage AnswerConsentForm( HttpResponseMessage m, bool rememberConsent )
        {
            return null;
        }

        HttpResponseMessage PostAcceptedResult( HttpResponseMessage m )
        {
            return null;
        }

    }
}
