using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApp.Tests
{
    static class WebAppUrl
    {
        public const string EnsureBasicUser = "/app/ensureBasicUser";

        public const string StartLoginUri = "/.webfront/c/startLogin";
        public const string BasicLoginUri = "/.webfront/c/basicLogin";
        public const string LoginUri = "/.webfront/c/unsafeDirectLogin";
        public const string RefreshUri = "/.webfront/c/refresh";
        public const string LogoutUri = "/.webfront/c/logout";
        public const string TokenExplainUri = "/.webfront/token";

    }
}
