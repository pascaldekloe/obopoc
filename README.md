# OBO POC

This repository hosts a proof-of-concept, which covers the entire on-behalf-of
flow with Microsoft's cloud service Kusto. The command walks the user through
(1) a login in as client, (2) an access token swap with a service principal, and
(3) a database query with the on-behalf-of token.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).


# Run

Configure your cloud configuration directly in the [Go code](https://github.com/pascaldekloe/obopoc/blob/ae5e231a7df3210e3f6a8673c43a661623048840/poc.go#L27).

Create an `app-secret.txt` file with the secret value for your service principal. A single line of text is expected, as defined on the [Azure portal](https://portal.azure.com/) under “App Registrations” → the respective application → “Manage” → “Certificates & secrets” → “Client secrets”.

Finally execute the command by running `go run poc.go`. The open the URL prompted in a browser, logon with your client credentials, and enter the redirect URL into the command prompt.


# Findings

Azure does not support the standardised RFC 8693 “OAuth 2.0 Token Exchange”. Active Directory provides a [custom HTTP call](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow) instead.

The on-behalf-of swap only works with so called “ID tokens”—regular OAuth2 access tokens are denied. Note that ID tokens must be enabled with a checkbox found on the [Azure portal](https://portal.azure.com/) under “App Registrations” → the respective application → “Manage” → “Authentication”.

The service secret is required for every token swap. Microsoft releases a newly developed [client library](https://github.com/AzureAD/microsoft-authentication-library-for-go) soon, which seems to rely on caching.

The client token must already have the respective “Azure Data Explorer Cluster” scope [OAuth2] (URI). That is, the token swap does not support cross-application switching.

In addtion to the cluster URI mentioned above, both the “openid” and the “profile” scopes [OAuth2] are required 

In addition to the “Microsoft Graph” `User.Read`, a special “Azure Data Explorer” `user_consent` permission must be enabled on the [Azure portal](https://portal.azure.com/)  under “App Registrations” → the respective application → “Manage” → “API permissions”.
