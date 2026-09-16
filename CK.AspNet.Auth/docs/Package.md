An authentication scheme for a front-end application talking to its API: a bearer token, optional
cookies, and endpoints under one entry path, `/.webfront`.

Expirations of different natures. The real authentication defaults to twenty minutes and can slide;
a long-lived "unsafe" one outlives it, remembering this browser without authenticating it, and who
was on it when asked to. Cookies can be scoped to the auth endpoints, set at the root, or disabled.

Login validation, account creation, provider binding, impersonation, dynamic scopes and the unsafe
direct login are each an optional service you implement. The token and the auth cookie go through the
Data Protection API.
