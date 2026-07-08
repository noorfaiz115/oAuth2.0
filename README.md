# Angular + .NET Google OAuth 2.0 OpenID Connect PKCE

This sample implements a production-style login flow:

- Angular starts the OAuth 2.0 authorization code flow with PKCE.
- Google authenticates the user.
- .NET exchanges the authorization code with Google.
- .NET verifies the Google ID token signature and required claims.
- .NET checks whether the Google user exists in the application user store.
- .NET creates your application's own JWT only for active app users.

The important mindset:

```text
Google authenticates the person.
Your application database authorizes the person.
Your application JWT represents your app's login/session decision.
```

## Project Structure

```text
angular-dotnet-google-oidc-pkce/
  client/   Angular SPA
  server/   .NET 9 Minimal API
```

Important files:

```text
client/src/app/auth.service.ts       Angular PKCE, redirect, callback handling
client/src/app/app.component.ts      Starts and finishes login
client/src/app/auth.models.ts        Angular request/response models
server/Program.cs                    Token exchange, ID token validation, app JWT creation
server/appsettings.json              Google config, app JWT config, demo app users
```

## Google Cloud Setup

Create an OAuth 2.0 **Web application** client in Google Cloud Console.

Add this Authorized JavaScript origin:

```text
http://localhost:4200
```

Add this Authorized redirect URI:

```text
http://localhost:4200/auth/callback
```

Copy the Client ID and Client Secret into:

```text
server/appsettings.json
```

Also replace this demo user email with your Google email:

```json
"ApplicationUsers": {
  "Users": [
    {
      "Id": "app-user-001",
      "GoogleSubject": "",
      "Email": "replace-with-your-google-email@example.com",
      "DisplayName": "Demo User",
      "Roles": ["User"],
      "IsActive": true
    }
  ]
}
```

For production, store `GoogleOidc:ClientSecret` and `AppJwt:SigningKey` in user
secrets, environment variables, or a vault. Do not commit real secrets.

## Run

Backend:

```powershell
cd C:\Project_AI_Learning\oAuth2.0\angular-dotnet-google-oidc-pkce\server
dotnet restore --configfile NuGet.Config
dotnet run --urls http://localhost:5098
```

Angular:

```powershell
cd C:\Project_AI_Learning\oAuth2.0\angular-dotnet-google-oidc-pkce\client
npm install
npm start
```

Open:

```text
http://localhost:4200
```

## Complete Flow

## 1. User Clicks Login

File:

```text
client/src/app/app.component.ts
```

`login()` calls:

```ts
this.auth.startLogin()
```

## 2. Angular Loads OIDC Config From .NET

File:

```text
client/src/app/auth.service.ts
```

Angular calls:

```text
GET http://localhost:5098/auth/config
```

.NET returns:

- Google Client ID
- Redirect URI
- Google authorization endpoint
- Scopes

The Google Client Secret is never sent to Angular.

## 3. Angular Creates PKCE And OIDC Values

File:

```text
client/src/app/auth.service.ts
```

Method:

```ts
startLogin()
```

Angular creates:

```text
code_verifier
code_challenge
state
nonce
```

Meaning:

- `code_verifier`: random secret kept in browser `sessionStorage`
- `code_challenge`: SHA-256 hash of `code_verifier`, sent to Google
- `state`: CSRF protection value, checked after callback
- `nonce`: OpenID Connect replay protection value, checked inside the ID token

## 4. Angular Redirects To Google

Angular redirects the browser to:

```text
https://accounts.google.com/o/oauth2/v2/auth
```

With query values:

```text
client_id
redirect_uri
response_type=code
scope=openid profile email
state
nonce
code_challenge
code_challenge_method=S256
prompt=select_account
```

At this point, your browser leaves Angular and opens Google's login page.

## 5. Google Authenticates The User

Google checks:

- Client ID is valid
- JavaScript origin is allowed
- Redirect URI is allowed
- User approved the requested scopes

The `openid` scope is what makes this OpenID Connect.

## 6. Google Redirects Back To Angular

Google redirects to:

```text
http://localhost:4200/auth/callback?code=...&state=...
```

Google sends an authorization code, not tokens.

## 7. Angular Validates State And Sends Code To .NET

File:

```text
client/src/app/auth.service.ts
```

Method:

```ts
completeLogin()
```

Angular checks:

```text
URL state === sessionStorage state
```

Then Angular sends:

```text
POST http://localhost:5098/auth/token
```

Body:

```json
{
  "code": "AUTHORIZATION_CODE_FROM_GOOGLE",
  "codeVerifier": "ORIGINAL_PKCE_CODE_VERIFIER",
  "redirectUri": "http://localhost:4200/auth/callback",
  "nonce": "ORIGINAL_OIDC_NONCE"
}
```

## 8. .NET Exchanges The Code With Google

File:

```text
server/Program.cs
```

Endpoint:

```csharp
app.MapPost("/auth/token", ...)
```

.NET sends this to Google:

```text
POST https://oauth2.googleapis.com/token
```

With:

```text
client_id
client_secret
code
code_verifier
grant_type=authorization_code
redirect_uri
```

Google checks that the `code_verifier` matches the original PKCE
`code_challenge`.

## 9. Google Returns Tokens To .NET

Google returns:

```json
{
  "access_token": "...",
  "expires_in": 3599,
  "scope": "openid profile email",
  "token_type": "Bearer",
  "id_token": "..."
}
```

Important difference:

- `access_token`: used to call Google APIs
- `id_token`: OpenID Connect token containing identity claims

## 10. .NET Verifies The Google ID Token

File:

```text
server/Program.cs
```

Class:

```csharp
GoogleIdTokenValidator
```

The backend verifies:

- JWT format
- Algorithm is `RS256`
- Google signing key exists in Google's JWKS endpoint
- RSA signature is valid
- Issuer is Google
- Audience equals your Google Client ID
- Expiry time has not passed
- Issue time is not in the future
- Nonce equals the original Angular nonce
- `sub`, `email`, and `email_verified` claims exist
- Email is verified

Google JWKS endpoint:

```text
https://www.googleapis.com/oauth2/v3/certs
```

If this validation fails, the backend returns `401 Unauthorized`.

## 11. .NET Checks The Application User Store

File:

```text
server/Program.cs
```

Class:

```csharp
ApplicationUserRepository
```

The current learning version uses `ApplicationUsers` in `appsettings.json` as a
simple user store. The backend allows login only when:

- Google `sub` matches `GoogleSubject`, or
- Google `email` matches `Email`
- And `IsActive` is `true`

If the user is missing or inactive, the backend returns `403 Forbidden`.

For a real database, use a table like:

```text
ApplicationUsers
  Id
  GoogleSubject
  Email
  DisplayName
  IsActive

ApplicationUserRoles
  UserId
  Role
```

Matching by `GoogleSubject` is best because Google's `sub` is stable and unique.

## 12. .NET Creates Your Application JWT

File:

```text
server/Program.cs
```

Class:

```csharp
AppJwtTokenFactory
```

The application JWT includes:

- App issuer
- App audience
- App user ID
- Email
- Display name
- Google subject ID
- Roles
- Expiry
- JWT ID

This token is your app's token. Use it when calling your own protected APIs.

## 13. Angular Displays The Result

File:

```text
client/src/app/app.component.html
```

Angular displays:

- Name
- Email
- Profile picture
- Google subject ID
- Email verified status
- Application roles
- Application JWT metadata
- Google token metadata

## Debugging Guide

## Debug Point 1: Before Redirecting To Google

File:

```text
client/src/app/auth.service.ts
```

Method:

```ts
startLogin()
```

Check:

```text
config.clientId
config.redirectUri
config.authorizationEndpoint
codeVerifier
codeChallenge
state
nonce
query.toString()
```

Browser storage:

```text
DevTools -> Application -> Session Storage -> http://localhost:4200
```

Expected keys:

```text
oidc_pkce_code_verifier
oidc_state
oidc_nonce
```

## Debug Point 2: Callback From Google

Expected URL:

```text
http://localhost:4200/auth/callback?code=...&state=...
```

If you see `error=redirect_uri_mismatch`, fix the redirect URI in Google Cloud.

## Debug Point 3: Completing Login In Angular

File:

```text
client/src/app/auth.service.ts
```

Method:

```ts
completeLogin()
```

Check:

```text
code
state
expectedState
codeVerifier
nonce
request
```

Important:

- `code` should not be empty
- `state` should equal `expectedState`
- `codeVerifier` should not be empty
- `nonce` should not be empty

## Debug Point 4: Backend Token Endpoint

File:

```text
server/Program.cs
```

Breakpoint:

```csharp
app.MapPost("/auth/token", async (...)
```

Check:

```text
request.Code
request.CodeVerifier
request.RedirectUri
request.Nonce
options.ClientId
options.TokenEndpoint
```

Do not print or share the real Client Secret.

## Debug Point 5: Google Token Response

Inspect:

```csharp
response.StatusCode
responseJson
```

Successful response contains:

```text
access_token
expires_in
scope
token_type
id_token
```

## Debug Point 6: Google ID Token Validation

File:

```text
server/Program.cs
```

Class:

```csharp
GoogleIdTokenValidator
```

Useful methods:

```csharp
ValidateAsync(...)
VerifySignature(...)
```

Check:

```text
header.Algorithm
header.KeyId
issuer
audience
expiresAt
issuedAt
nonce
subject
email
emailVerified
```

If this fails, you get `401 Unauthorized`.

## Debug Point 7: App User Lookup

File:

```text
server/Program.cs
```

Class:

```csharp
ApplicationUserRepository
```

Method:

```csharp
FindActiveUser(...)
```

Check:

```text
googleIdentity.Subject
googleIdentity.Email
user.GoogleSubject
user.Email
user.IsActive
```

If this returns `null`, you get `403 Forbidden`.

## Debug Point 8: App JWT Creation

File:

```text
server/Program.cs
```

Class:

```csharp
AppJwtTokenFactory
```

Method:

```csharp
CreateToken(...)
```

Check:

```text
user.Id
user.Roles
options.Issuer
options.Audience
expiresAt
```

## Common Errors

## `redirect_uri_mismatch`

Google Cloud Authorized redirect URI must exactly match:

```text
http://localhost:4200/auth/callback
```

## `origin_mismatch`

Google Cloud Authorized JavaScript origin must include:

```text
http://localhost:4200
```

## `invalid_grant`

Common causes:

- Authorization code was already used
- Authorization code expired
- Wrong `redirect_uri`
- Wrong or missing `code_verifier`
- Callback page was refreshed after the code was already exchanged

## `invalid_client`

Common causes:

- Wrong Client ID
- Wrong Client Secret
- Wrong OAuth client type

Use OAuth client type:

```text
Web application
```

## `401 Unauthorized` From `/auth/token`

Google login happened, but the backend rejected the ID token.

Common causes:

- Wrong Google Client ID in backend config
- Token expired
- Nonce mismatch
- Issuer or audience mismatch
- Google signing key could not be matched

## `403 Forbidden` From `/auth/token`

Google identity is valid, but the user is not allowed in your app.

Common causes:

- Email is not in `ApplicationUsers`
- `GoogleSubject` does not match Google `sub`
- `IsActive` is `false`

Fix by adding the user to your application database/user store.

## CORS Error

Angular runs here:

```text
http://localhost:4200
```

.NET runs here:

```text
http://localhost:5098
```

If you change Angular's port, update CORS in `server/Program.cs`.

## What To Verify

Before login:

- Backend is running on `http://localhost:5098`
- Angular is running on `http://localhost:4200`
- `/auth/config` returns your Google Client ID
- Google Cloud has the correct JavaScript origin
- Google Cloud has the correct redirect URI
- Your Google email or Google subject ID exists in the app user store

During login:

- `code_verifier` is created
- `code_challenge` is created
- `state` is saved
- `nonce` is saved
- Browser redirects to Google

After callback:

- URL contains `code`
- URL contains `state`
- Returned `state` matches stored `state`
- `code_verifier` still exists
- `nonce` still exists
- Angular posts to `/auth/token`

Backend:

- .NET receives code, verifier, redirect URI, and nonce
- .NET exchanges the code with Google
- Google returns an `id_token`
- .NET verifies the `id_token`
- .NET finds an active app user
- .NET creates an application JWT
- Angular displays profile and app JWT metadata

## Production Notes

This project now implements the important production security flow, but it still
uses config as a simple user store so the code is easy to study.

Before real production:

- Replace `ApplicationUsers` config with your real database
- Match users by Google `sub` when possible
- Store Google Client Secret in user secrets, environment variables, or a vault
- Store app JWT signing key in user secrets, environment variables, or a vault
- Use HTTPS
- Add JWT bearer authentication middleware for protected APIs
- Consider issuing a secure HTTP-only cookie instead of storing JWTs in browser storage
- Add refresh/session management if your app needs long-lived sessions
