using CK.Core;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace CK.AspNet.Auth
{
    // TODO: use System.Text.Json.
    static class ObsoleteStringMatcher
    {
        /// <summary>
        /// The <see cref="Regex"/> that <see cref="TryMatchDoubleValue(StringMatcher)"/> uses to avoid
        /// calling <see cref="double.TryParse(string, out double)"/> when resolving the value is 
        /// useless.
        /// Note that this regex allow a leading minus (-) sign, but not a plus (+).
        /// </summary>
        static public readonly Regex RegexDouble = new Regex( @"^-?(0|[1-9][0-9]*)(\.[0-9]+)?((e|E)(\+|-)?[0-9]+)?", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture );

        /// <summary>
        /// Matches a double without getting its value nor setting an error if match fails.
        /// This uses <see cref="RegexDouble"/>.
        /// The text may start with a minus (-) but not with a plus (+).
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <returns><c>true</c> when matched, <c>false</c> otherwise.</returns>
        public static bool TryMatchDoubleValue( this StringMatcher @this )
        {
            Match m = RegexDouble.Match( @this.Text, @this.StartIndex, @this.Length );
            if( !m.Success ) return false;
            return @this.UncheckedMove( m.Length );
        }

        /// <summary>
        /// Matches a double and gets its value. No error is set if match fails.
        /// The text may start with a minus (-) but not with a plus (+).
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <param name="value">The read value on success.</param>
        /// <returns><c>true</c> when matched, <c>false</c> otherwise.</returns>
        public static bool TryMatchDoubleValue( this StringMatcher @this, out double value )
        {
            Match m = RegexDouble.Match( @this.Text, @this.StartIndex, @this.Length );
            if( !m.Success )
            {
                value = 0;
                return false;
            }
            if( !double.TryParse( @this.Text.Substring( @this.StartIndex, m.Length ), NumberStyles.Float, CultureInfo.InvariantCulture, out value ) ) return false;
            return @this.UncheckedMove( m.Length );
        }

        /// <summary>
        /// Tries to match a //.... or /* ... */ comment.
        /// Proper termination of comment (by a new line or the closing */) is not required: 
        /// a ending /*... is considered valid.
        /// </summary>
        /// <param name="this">This <see cref="IStringMatcher"/>.</param>
        /// <returns>True on success, false if the <see cref="IStringMatcher.Head"/> is not on a /.</returns>
        public static bool TryMatchJSComment( this StringMatcher @this )
        {
            if( !@this.TryMatchChar( '/' ) ) return false;
            if( @this.TryMatchChar( '/' ) )
            {
                while( !@this.IsEnd && @this.Head != '\n' ) @this.UncheckedMove( 1 );
                if( !@this.IsEnd ) @this.UncheckedMove( 1 );
                return true;
            }
            else if( @this.TryMatchChar( '*' ) )
            {
                while( !@this.IsEnd )
                {
                    if( @this.Head == '*' )
                    {
                        @this.UncheckedMove( 1 );
                        if( @this.IsEnd || @this.TryMatchChar( '/' ) ) return true;
                    }
                    @this.UncheckedMove( 1 );
                }
                return true;
            }
            @this.UncheckedMove( -1 );
            return false;
        }

        /// <summary>
        /// Skips any white spaces or JS comments (//... or /* ... */) and always returns true.
        /// </summary>
        /// <param name="this">This <see cref="IStringMatcher"/>.</param>
        /// <returns>Always true to ease composition.</returns>
        public static bool SkipWhiteSpacesAndJSComments( this StringMatcher @this )
        {
            @this.MatchWhiteSpaces( 0 );
            while( @this.TryMatchJSComment() ) @this.MatchWhiteSpaces( 0 );
            return true;
        }

        /// <summary>
        /// Matches a JSON quoted string without setting an error if match fails.
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <param name="content">Extracted content.</param>
        /// <param name="allowNull">True to allow 'null'.</param>
        /// <returns><c>true</c> when matched, <c>false</c> otherwise.</returns>
        public static bool TryMatchJSONQuotedString( this StringMatcher @this, out string? content, bool allowNull = false )
        {
            content = null;
            if( @this.IsEnd ) return false;
            int i = @this.StartIndex;
            if( @this.Text[i++] != '"' )
            {
                return allowNull && @this.TryMatchText( "null" );
            }
            int len = @this.Length - 1;
            StringBuilder? b = null;
            while( len >= 0 )
            {
                if( len == 0 ) return false;
                char c = @this.Text[i++];
                --len;
                if( c == '"' ) break;
                if( c == '\\' )
                {
                    if( len == 0 ) return false;
                    if( b == null ) b = new StringBuilder( @this.Text, @this.StartIndex + 1, i - @this.StartIndex - 2, 1024 );
                    switch( (c = @this.Text[i++]) )
                    {
                        case 'r': c = '\r'; break;
                        case 'n': c = '\n'; break;
                        case 'b': c = '\b'; break;
                        case 't': c = '\t'; break;
                        case 'f': c = '\f'; break;
                        case 'u':
                            {
                                if( --len == 0 ) return false;
                                int cN;
                                cN = @this.Text[i++].HexDigitValue();
                                if( cN < 0 || cN > 15 ) return false;
                                int val = cN << 12;
                                if( --len == 0 ) return false;
                                cN = @this.Text[i++].HexDigitValue();
                                if( cN < 0 || cN > 15 ) return false;
                                val |= cN << 8;
                                if( --len == 0 ) return false;
                                cN = @this.Text[i++].HexDigitValue();
                                if( cN < 0 || cN > 15 ) return false;
                                val |= cN << 4;
                                if( --len == 0 ) return false;
                                cN = @this.Text[i++].HexDigitValue();
                                if( cN < 0 || cN > 15 ) return false;
                                val |= cN;
                                c = (char)val;
                                break;
                            }
                    }
                }
                if( b != null ) b.Append( c );
            }
            int lenS = i - @this.StartIndex;
            if( b != null ) content = b.ToString();
            else content = @this.Text.Substring( @this.StartIndex + 1, lenS - 2 );
            return @this.UncheckedMove( lenS );
        }


        /// <summary>
        /// Matches a quoted string without extracting its content.
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <param name="allowNull">True to allow 'null'.</param>
        /// <returns><c>true</c> when matched, <c>false</c> otherwise.</returns>
        public static bool TryMatchJSONQuotedString( this StringMatcher @this, bool allowNull = false )
        {
            if( @this.IsEnd ) return false;
            int i = @this.StartIndex;
            if( @this.Text[i++] != '"' )
            {
                return allowNull && @this.TryMatchText( "null" );
            }
            int len = @this.Length - 1;
            while( len >= 0 )
            {
                if( len == 0 ) return false;
                char c = @this.Text[i++];
                --len;
                if( c == '"' ) break;
                if( c == '\\' )
                {
                    i++;
                    --len;
                }
            }
            return @this.UncheckedMove( i - @this.StartIndex );
        }

        /// <summary>
        /// Matches a JSON terminal value: a "string", null, a number (double value), true or false.
        /// This method ignores the actual value and does not set any error if match fails.
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <returns>True if a JSON value has been matched, false otherwise.</returns>
        public static bool TryMatchJSONTerminalValue( this StringMatcher @this )
        {
            return @this.TryMatchJSONQuotedString( true )
                    || @this.TryMatchDoubleValue()
                    || @this.TryMatchText( "true" )
                    || @this.TryMatchText( "false" );
        }

        /// <summary>
        /// Matches a JSON terminal value: a "string", null, a number (double value), true or false.
        /// No error is set if match fails.
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <param name="value">The parsed value. Can be null.</param>
        /// <returns>True if a JSON value has been matched, false otherwise.</returns>
        public static bool TryMatchJSONTerminalValue( this StringMatcher @this, out object? value )
        {
            string s;
            if( @this.TryMatchJSONQuotedString( out s, true ) )
            {
                value = s;
                return true;
            }
            double d;
            if( @this.TryMatchDoubleValue( out d ) )
            {
                value = d;
                return true;
            }
            if( @this.TryMatchText( "true" ) )
            {
                value = true;
                return true;
            }
            if( @this.TryMatchText( "false" ) )
            {
                value = false;
                return true;
            }
            value = null;
            return false;
        }

        /// <summary>
        /// Matches a very simple version of a JSON object content: this match stops at the first closing }.
        /// Whitespaces and JS comments (//... or /* ... */) are skipped.
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <param name="o">The read object on success as a list of KeyValuePair.</param>
        /// <returns>True on success, false on error.</returns>
        public static bool MatchJSONObjectContent( this StringMatcher @this, out List<KeyValuePair<string, object>>? o )
        {
            o = null;
            while( !@this.IsEnd )
            {
                @this.SkipWhiteSpacesAndJSComments();
                string? propName;
                object value;
                if( @this.TryMatchChar( '}' ) )
                {
                    if( o == null ) o = new List<KeyValuePair<string, object>>();
                    return true;
                }
                if( !@this.TryMatchJSONQuotedString( out propName ) )
                {
                    o = null;
                    return @this.SetError( "Quoted Property Name." );
                }
                @this.SkipWhiteSpacesAndJSComments();
                if( !@this.MatchChar( ':' ) || !MatchJSONObject( @this, out value ) )
                {
                    o = null;
                    return false;
                }
                if( o == null ) o = new List<KeyValuePair<string, object>>();
                o.Add( new KeyValuePair<string, object>( propName, value ) );
                @this.SkipWhiteSpacesAndJSComments();
                // This accepts e trailing comma at the end of a property list: ..."a":0,} is not an error.
                @this.TryMatchChar( ',' );
            }
            return @this.SetError( "JSON object definition but reached end of match." );
        }

        /// <summary>
        /// Matches a { "JSON" : "object" }, a ["JSON", "array"] or a terminal value (string, null, double, true or false) 
        /// and any combination of them.
        /// Whitespaces and JS comments (//... or /* ... */) are skipped.
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <param name="value">
        /// A list of objects (for array), a list of KeyValuePair&lt;string,object&gt; for object or
        /// a double, string, boolean or null (for null).</param>
        /// <returns>True on success, false on error.</returns>
        public static bool MatchJSONObject( this StringMatcher @this, out object value )
        {
            value = null;
            @this.SkipWhiteSpacesAndJSComments();
            if( @this.TryMatchChar( '{' ) )
            {
                List<KeyValuePair<string, object>> c;
                if( !MatchJSONObjectContent( @this, out c ) ) return false;
                value = c;
                return true;
            }
            if( @this.TryMatchChar( '[' ) )
            {
                List<object> t;
                if( !MatchJSONArrayContent( @this, out t ) ) return false;
                value = t;
                return true;
            }
            if( TryMatchJSONTerminalValue( @this, out value ) ) return true;
            return @this.SetError( "JSON value." );
        }

        /// <summary>
        /// Matches a JSON array content: the match ends with the first ].
        /// Whitespaces and JS comments (//... or /* ... */) are skipped.
        /// </summary>
        /// <param name="this">This <see cref="StringMatcher"/>.</param>
        /// <param name="value">The list of objects on success.</param>
        /// <returns>True on success, false otherwise.</returns>
        public static bool MatchJSONArrayContent( this StringMatcher @this, out List<object> value )
        {
            value = null;
            while( !@this.IsEnd )
            {
                @this.SkipWhiteSpacesAndJSComments();
                if( @this.TryMatchChar( ']' ) )
                {
                    if( value == null ) value = new List<object>();
                    return true;
                }
                object cell;
                if( !MatchJSONObject( @this, out cell ) ) return false;
                if( value == null ) value = new List<object>();
                value.Add( cell );
                @this.SkipWhiteSpacesAndJSComments();
                // Allow trailing comma: ,] is valid.
                @this.TryMatchChar( ',' );
            }
            return @this.SetError( "JSON array definition but reached end of match." );
        }

    }
}
