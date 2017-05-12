using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    /// <summary>
    /// Client helper.
    /// </summary>
    public class TestClient : IDisposable
    {
        readonly Uri _baseAddress;
        readonly HttpClientHandler _handler;
        readonly HttpClient _httpClient;
        string _token;

        /// <summary>
        /// Initializes a new client.
        /// </summary>
        public TestClient(string baseAdress )
        {
            _baseAddress = new Uri(baseAdress);
            _handler = new HttpClientHandler()
            {
                CookieContainer = new CookieContainer()
            };
            _httpClient = new HttpClient(_handler)
            {
                BaseAddress = _baseAddress,
            };
        }

        /// <summary>
        /// Gets the base address.
        /// </summary>
        public Uri BaseAddress => _baseAddress;

        /// <summary>
        /// Gets or sets the authorization header (defaults to "Authorization").
        /// When <see cref="SetToken"/> is called with a non null token, 
        /// requests have the 'AuthorizationHeaderName Bearer token" added.
        /// </summary>
        public string AuthorizationHeaderName { get; set; } = "Authorization";

        /// <summary>
        /// Sets the authorization token or clears it (by setting it to null).
        /// </summary>
        public string Token
        {
            get => _token;
            set
            {
                if( _token != value )
                {
                    if (_token != null) _httpClient.DefaultRequestHeaders.Remove("Authorization");
                    _token = value;
                    if (_token != null) _httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + _token);
                }
            }
        }

        /// <summary>
        /// Gets the <see cref="CookieContainer"/>.
        /// </summary>
        public CookieContainer Cookies => _handler.CookieContainer;

        /// <summary>
        /// Issues a GET request to the relative url on <see cref="TestServer.BaseAddress"/>.
        /// </summary>
        /// <param name="relativeUrl">The relative url.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Get(string relativeUrl)
        {
            return Get(new Uri(relativeUrl, UriKind.Relative));
        }

        /// <summary>
        /// Issues a GET request to the relative url on <see cref="TestServer.BaseAddress"/>.
        /// </summary>
        /// <param name="relativeUrl">The relative url.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Get(Uri relativeUrl)
        {
            var absoluteUrl = new Uri(_baseAddress, relativeUrl);
            return _httpClient.GetAsync(absoluteUrl).Result;
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> with form values.
        /// </summary>
        /// <param name="relativeUrl">The relative url.</param>
        /// <param name="formValues">The form values.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post(string relativeUrl, IDictionary<string, string> formValues)
        {
            return Post(new Uri(relativeUrl, UriKind.Relative), formValues);
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> with form values.
        /// </summary>
        /// <param name="relativeUrl">The relative url.</param>
        /// <param name="formValues">The form values.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post(Uri relativeUrl, IDictionary<string, string> formValues)
        {
            return Post(relativeUrl, new FormUrlEncodedContent(formValues));
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> with an "application/json"
        /// contnent.
        /// </summary>
        /// <param name="relativeUrl">The relative url.</param>
        /// <param name="json">The json content.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post(string relativeUrl, string json)
        {
            var c = new StringContent(json);
            c.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
            return Post(new Uri(relativeUrl, UriKind.Relative), c);
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> with an <see cref="HttpContent"/>.
        /// </summary>
        /// <param name="relativeUrl">The relative url.</param>
        /// <param name="content">The content.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post(Uri relativeUrl, HttpContent content)
        {
            var absoluteUrl = new Uri(_baseAddress, relativeUrl);
            return _httpClient.PostAsync(absoluteUrl, content).Result;
        }

        /// <summary>
        /// Follows the reddirected url if the response's status is <see cref="HttpStatusCode.Moved"/> (301) 
        /// or <see cref="HttpStatusCode.Found"/> (302).
        /// A redirection always uses the GET method.
        /// </summary>
        /// <param name="response">The initial response.</param>
        /// <returns>The redirected response.</returns>
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

        public void Dispose()
        {
            _httpClient.Dispose();
        }
    }
}


