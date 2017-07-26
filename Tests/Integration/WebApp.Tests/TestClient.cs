using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        int _maxAutomaticRedirections;

        /// <summary>
        /// Initializes a new client.
        /// </summary>
        public TestClient( string baseAdress )
        {
            _baseAddress = new Uri( baseAdress );
            _handler = new HttpClientHandler()
            {
                CookieContainer = new CookieContainer(),
                AllowAutoRedirect = false
            };
            _maxAutomaticRedirections = 50;
            _httpClient = new HttpClient( _handler )
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
                    if( _token != null ) _httpClient.DefaultRequestHeaders.Remove( "Authorization" );
                    _token = value;
                    if( _token != null ) _httpClient.DefaultRequestHeaders.Add( "Authorization", "Bearer " + _token );
                }
            }
        }

        /// <summary>
        /// Gets the <see cref="CookieContainer"/>.
        /// </summary>
        public CookieContainer Cookies => _handler.CookieContainer;

        /// <summary>
        /// Clears cookies from <see cref="BaseAddress"/> and optional sub paths.
        /// </summary>
        public void ClearCookies( params string[] subPath ) => ClearCookies( _baseAddress, subPath );

        /// <summary>
        /// Clears cookies from a base path and optional sub paths.
        /// </summary>
        /// <param name="basePath">The base url. Should not be null.</param>
        /// <param name="subPaths">Sub paths for which cookies must be cleared.</param>
        public void ClearCookies( Uri basePath, IEnumerable<string> subPaths )
        {
            foreach( Cookie c in _handler.CookieContainer.GetCookies( basePath ) )
            {
                c.Expired = true;
            }
            if( subPaths != null )
            {
                foreach( string u in subPaths )
                {
                    if( string.IsNullOrWhiteSpace( u ) ) continue;
                    Uri normalized = new Uri( basePath, u[u.Length - 1] != '/' ? u + '/' : u );
                    foreach( Cookie c in _handler.CookieContainer.GetCookies( normalized ) )
                    {
                        c.Expired = true;
                    }
                }
            }
        }

        /// <summary>
        /// Clears cookies from a base path and sub paths.
        /// </summary>
        /// <param name="basePath">The base url. Should not be null.</param>
        /// <param name="subPaths">Optional sub paths for which cookies must be cleared.</param>
        public void ClearCookies( Uri basePath, params string[] subPath ) => ClearCookies( basePath, (IEnumerable<string>)subPath );

        /// <summary>
        /// Issues a GET request to the relative url on <see cref="TestServer.BaseAddress"/> or to an absolute url.
        /// </summary>
        /// <param name="relativeUrl">The BaseAddress relative url or an absolute url.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Get( string relativeUrl )
        {
            return Get( new Uri( relativeUrl, UriKind.RelativeOrAbsolute ) );
        }

        /// <summary>
        /// Issues a GET request to the relative url on <see cref="TestServer.BaseAddress"/> or to an absolute url.
        /// </summary>
        /// <param name="relativeUrl">The BaseAddress relative url or an absolute url.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Get( Uri relativeUrl )
        {
            var absoluteUrl = new Uri( _baseAddress, relativeUrl );
            return AutoFollowRedirect( _httpClient.GetAsync( absoluteUrl ).Result );
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> or to an absolute url
        /// with form values.
        /// </summary>
        /// <param name="relativeUrl">The BaseAddress relative url or an absolute url.</param>
        /// <param name="formValues">The form values.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post( string relativeUrl, IEnumerable<KeyValuePair<string, string>> formValues )
        {
            return Post( new Uri( relativeUrl, UriKind.RelativeOrAbsolute ), formValues );
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> or to an absolute url
        /// with form values.
        /// </summary>
        /// <param name="relativeUrl">The BaseAddress relative url or an absolute url.</param>
        /// <param name="formValues">The form values.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post( Uri relativeUrl, IEnumerable<KeyValuePair<string, string>> formValues )
        {
            return Post( relativeUrl, new FormUrlEncodedContent( formValues ) );
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> or to an absolute url 
        /// with an "application/json"
        /// contnent.
        /// </summary>
        /// <param name="relativeUrl">The BaseAddress relative url or an absolute url.</param>
        /// <param name="json">The json content.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post( string relativeUrl, string json )
        {
            var c = new StringContent( json );
            c.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse( "application/json" );
            return Post( new Uri( relativeUrl, UriKind.RelativeOrAbsolute ), c );
        }

        /// <summary>
        /// Issues a POST request to the relative url on <see cref="TestServer.BaseAddress"/> or to an absolute url 
        /// with an <see cref="HttpContent"/>.
        /// </summary>
        /// <param name="relativeUrl">The BaseAddress relative url or an absolute url.</param>
        /// <param name="content">The content.</param>
        /// <returns>The response.</returns>
        public HttpResponseMessage Post( Uri relativeUrl, HttpContent content )
        {
            var absoluteUrl = new Uri( _baseAddress, relativeUrl );
            return AutoFollowRedirect( _httpClient.PostAsync( absoluteUrl, content ).Result );
        }

        HttpResponseMessage AutoFollowRedirect( HttpResponseMessage m )
        {
            int redirection = _maxAutomaticRedirections;
            while( --redirection >= 0 )
            {
                var next = FollowRedirect( m, throwIfNotRedirect: false );
                if( next == m ) break;
                m = next;
            }
            return m;
        }


        /// <summary>
        /// Gets or sets the maximum number of redirections that will be automatically followed.
        /// Defaults to 50.
        /// Set it to 0 to manually follow redirections thanks to <see cref="FollowRedirect(HttpResponseMessage, bool)"/>.
        /// </summary>
        public int MaxAutomaticRedirections
        {
            get => _maxAutomaticRedirections;
            set => _maxAutomaticRedirections = value <= 0 ? 0 : value;
        }

        /// <summary>
        /// Follows the redirected url if the response's status is <see cref="HttpStatusCode.Moved"/> (301) 
        /// or <see cref="HttpStatusCode.Found"/> (302).
        /// This should be used with a small or 0 <see cref="MaxAutomaticRedirections"/> value.
        /// A redirection always uses the GET method.
        /// </summary>
        /// <param name="response">The initial response.</param>
        /// <param name="throwIfNotRedirect">When the <paramref name="response"/> is not a 301 or 302 
        /// and this is true, this method throws an exception. When this parameter is false, the <paramref name="response"/>
        /// is returned (since it is the final redirected response).</param>
        /// <returns>The redirected response.</returns>
        public HttpResponseMessage FollowRedirect( HttpResponseMessage response, bool throwIfNotRedirect = false )
        {
            if( response.StatusCode != HttpStatusCode.Moved && response.StatusCode != HttpStatusCode.Found )
            {
                if( throwIfNotRedirect ) throw new Exception( "Response must be a 301 Moved or a 302 Found." );
                return response;
            }
            var redirectUrl = response.Headers.Location;
            if( !redirectUrl.IsAbsoluteUri )
            {
                redirectUrl = new Uri( response.RequestMessage.RequestUri, redirectUrl );
            }
            return _httpClient.GetAsync( redirectUrl ).Result;
        }

        public void Dispose()
        {
            _httpClient.Dispose();
        }
    }
}


