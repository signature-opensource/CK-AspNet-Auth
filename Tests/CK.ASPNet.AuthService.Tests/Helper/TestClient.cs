using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Net.Http.Headers;

namespace CK.AspNet.AuthService.Tests
{
    public class TestClient
    {
        readonly TestServer _testServer;
        string _token;

        public TestClient(TestServer testServer)
        {
            _testServer = testServer;
            Cookies = new CookieContainer();
        }

        public void SetToken(string token) => _token = token;

        public CookieContainer Cookies { get; }

        public HttpResponseMessage Get(string relativeUrl)
        {
            return Get(new Uri(relativeUrl, UriKind.Relative));
        }

        public HttpResponseMessage Get(Uri relativeUrl)
        {
            var absoluteUrl = new Uri(_testServer.BaseAddress, relativeUrl);
            var requestBuilder = _testServer.CreateRequest(absoluteUrl.ToString());
            AddCookies(requestBuilder, absoluteUrl);
            AddToken(requestBuilder);
            var response = requestBuilder.GetAsync().Result;
            UpdateCookies(response, absoluteUrl);
            return response;
        }
        void AddToken(RequestBuilder requestBuilder)
        {
            if(_token != null)
            {
                requestBuilder.AddHeader("Authorization", "Bearer " + _token );
            }
        }

        void AddCookies(RequestBuilder requestBuilder, Uri absoluteUrl)
        {
            var cookieHeader = Cookies.GetCookieHeader(absoluteUrl);
            if (!string.IsNullOrWhiteSpace(cookieHeader))
            {
                requestBuilder.AddHeader(HeaderNames.Cookie, cookieHeader);
            }
        }

        void UpdateCookies(HttpResponseMessage response, Uri absoluteUrl)
        {
            if (response.Headers.Contains(HeaderNames.SetCookie))
            {
                var cookies = response.Headers.GetValues(HeaderNames.SetCookie);
                foreach (var cookie in cookies)
                {
                    Cookies.SetCookies( absoluteUrl, cookie);
                }
            }
        }

        public HttpResponseMessage Post(string relativeUrl, IDictionary<string, string> formValues)
        {
            return Post(new Uri(relativeUrl, UriKind.Relative), formValues);
        }

        public HttpResponseMessage Post(Uri relativeUrl, IDictionary<string, string> formValues)
        {
            return Post(relativeUrl, new FormUrlEncodedContent(formValues));
        }

        public HttpResponseMessage Post(string relativeUrl, string json)
        {
            var c = new StringContent(json);
            c.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
            return Post(new Uri(relativeUrl, UriKind.Relative), c);
        }


        public HttpResponseMessage Post(Uri relativeUrl, HttpContent content)
        {
            var absoluteUrl = new Uri(_testServer.BaseAddress, relativeUrl);
            var requestBuilder = _testServer.CreateRequest(absoluteUrl.ToString());
            AddCookies(requestBuilder, absoluteUrl);
            AddToken(requestBuilder);
            var response = requestBuilder.And(message =>
            {
                message.Content = content;
            }).PostAsync().Result;
            UpdateCookies(response, absoluteUrl);
            return response;
        }

        public HttpResponseMessage FollowRedirect(HttpResponseMessage response)
        {
            if (response.StatusCode != HttpStatusCode.Moved && response.StatusCode != HttpStatusCode.Found)
            {
                return response;
            }
            var redirectUrl = new Uri(response.Headers.Location.ToString(), UriKind.RelativeOrAbsolute);
            if (redirectUrl.IsAbsoluteUri)
            {
                redirectUrl = new Uri(redirectUrl.PathAndQuery, UriKind.Relative);
            }
            return Get(redirectUrl);
        }
    }
}

