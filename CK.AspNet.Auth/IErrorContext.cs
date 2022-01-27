namespace CK.AspNet.Auth
{
    /// <summary>
    /// Internal that unifies <see cref="WebFrontAuthStartLoginContext"/> and <see cref="WebFrontAuthLoginContext"/>.
    /// </summary>
    interface IErrorContext
    {
        /// <summary>
        /// Sets an error identifier and message.
        /// Can be called multiple times: new error information replaces the previous one.
        /// </summary>
        /// <param name="errorId">Error identifier (a dotted identifier string).</param>
        /// <param name="errorMessage">The error message in clear text.</param>
        public void SetError( string errorId, string errorMessage );

        /// <summary>
        /// Gets whether an error has been set.
        /// </summary>
        bool HasError { get; }
    }

}
