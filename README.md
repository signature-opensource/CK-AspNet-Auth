# CK-AspNet-Auth

[![Licence](https://img.shields.io/github/license/signature-opensource/CK-AspNet-Auth.svg)](LICENSE)

WebFrontAuth: the authentication scheme a CKomposable front end uses against its API. A bearer token,
cookies you can scope or switch off, and a handful of endpoints under `/.webfront`.

| Package | Description | Latest stable |
|---------|-------------|---------------|
| [CK.AspNet.Auth](CK.AspNet.Auth/README.md) | The scheme: the endpoints, the expirations, the cookie modes and the services you implement to extend it. | [![nuget](https://img.shields.io/nuget/v/CK.AspNet.Auth.svg?label=CK.AspNet.Auth)](https://www.nuget.org/packages/CK.AspNet.Auth/) |
| [CK.Testing.AspNetServer.Auth](CK.Testing.AspNetServer.Auth/README.md) | Starts a real server with the scheme wired and a fake user database, so a test can log in immediately. | [![nuget](https://img.shields.io/nuget/v/CK.Testing.AspNetServer.Auth.svg?label=CK.Testing.AspNetServer.Auth)](https://www.nuget.org/packages/CK.Testing.AspNetServer.Auth/) |

This repository does not decide who your users are. The scheme consumes one contract,
`IWebFrontAuthLoginService`, and the test helper adds a second, `IUserInfoProvider`. The database
behind them lives elsewhere, and every implementation here is a test double.
