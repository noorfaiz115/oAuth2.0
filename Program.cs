using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<GoogleOidcOptions>(builder.Configuration.GetSection("GoogleOidc"));
builder.Services.Configure<AppJwtOptions>(builder.Configuration.GetSection("AppJwt"));
builder.Services.Configure<ApplicationUsersOptions>(builder.Configuration.GetSection("ApplicationUsers"));
builder.Services.AddHttpClient();
builder.Services.AddSingleton<GoogleIdTokenValidator>();
builder.Services.AddSingleton<ApplicationUserRepository>();
builder.Services.AddSingleton<AppJwtTokenFactory>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AngularDev", policy =>
    {
        policy
            .WithOrigins("http://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

var app = builder.Build();

app.UseCors("AngularDev");

app.MapGet("/", () => Results.Ok(new
{
    name = "Google OIDC PKCE API",
    endpoints = new[] { "/auth/config", "/auth/token" }
}));

app.MapGet("/auth/config", (IConfiguration configuration) =>
{
    var options = configuration.GetSection("GoogleOidc").Get<GoogleOidcOptions>() ?? new GoogleOidcOptions();

    if (string.IsNullOrWhiteSpace(options.ClientId) ||
        options.ClientId.StartsWith("PASTE_", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Problem(
            title: "Google Client ID is not configured.",
            detail: "Set GoogleOidc:ClientId in appsettings.json or user secrets.");
    }

    return Results.Ok(new AuthConfigResponse(
        options.ClientId,
        options.RedirectUri,
        options.AuthorizationEndpoint,
        options.Scopes));
});

app.MapPost("/auth/token", async (
    AuthCodeExchangeRequest request,
    IConfiguration configuration,
    IHttpClientFactory httpClientFactory,
    GoogleIdTokenValidator idTokenValidator,
    ApplicationUserRepository users,
    AppJwtTokenFactory appJwtTokenFactory) =>
{
    var options = configuration.GetSection("GoogleOidc").Get<GoogleOidcOptions>() ?? new GoogleOidcOptions();

    if (string.IsNullOrWhiteSpace(options.ClientId) ||
        string.IsNullOrWhiteSpace(options.ClientSecret) ||
        options.ClientId.StartsWith("PASTE_", StringComparison.OrdinalIgnoreCase) ||
        options.ClientSecret.StartsWith("PASTE_", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Problem(
            title: "Google OAuth credentials are not configured.",
            detail: "Set GoogleOidc:ClientId and GoogleOidc:ClientSecret before exchanging an authorization code.");
    }

    if (string.IsNullOrWhiteSpace(request.Code) ||
        string.IsNullOrWhiteSpace(request.CodeVerifier) ||
        string.IsNullOrWhiteSpace(request.RedirectUri) ||
        string.IsNullOrWhiteSpace(request.Nonce))
    {
        return Results.BadRequest(new { error = "code, codeVerifier, redirectUri, and nonce are required." });
    }

    var tokenRequest = new Dictionary<string, string>
    {
        ["client_id"] = options.ClientId,
        ["client_secret"] = options.ClientSecret,
        ["code"] = request.Code,
        ["code_verifier"] = request.CodeVerifier,
        ["grant_type"] = "authorization_code",
        ["redirect_uri"] = request.RedirectUri
    };

    using var http = httpClientFactory.CreateClient();
    using var response = await http.PostAsync(options.TokenEndpoint, new FormUrlEncodedContent(tokenRequest));
    var responseJson = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        return Results.Problem(
            title: "Google token exchange failed.",
            detail: responseJson,
            statusCode: (int)response.StatusCode);
    }

    var tokenResponse = JsonSerializer.Deserialize<GoogleTokenResponse>(
        responseJson,
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

    if (tokenResponse is null || string.IsNullOrWhiteSpace(tokenResponse.IdToken))
    {
        return Results.Problem(
            title: "Google did not return an ID token.",
            detail: responseJson);
    }

    GoogleIdentity googleIdentity;
    try
    {
        googleIdentity = await idTokenValidator.ValidateAsync(tokenResponse.IdToken, request.Nonce);
    }
    catch (SecurityException)
    {
        return Results.Unauthorized();
    }

    var appUser = users.FindActiveUser(googleIdentity);
    if (appUser is null)
    {
        return Results.Json(
            new { error = "Your Google account is valid, but this user is not registered or active in the application database." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    var appToken = appJwtTokenFactory.CreateToken(appUser, googleIdentity);
    var profile = new UserProfile(
        googleIdentity.Subject,
        appUser.DisplayName ?? googleIdentity.Name,
        googleIdentity.Email,
        googleIdentity.Picture,
        googleIdentity.EmailVerified,
        appUser.Roles);

    return Results.Ok(new AuthResult(
        profile,
        new TokenMetadata(
            tokenResponse.TokenType,
            tokenResponse.ExpiresIn,
            tokenResponse.Scope,
            HasAccessToken: !string.IsNullOrWhiteSpace(tokenResponse.AccessToken)),
        appToken));
});

app.Run();

public sealed class GoogleIdTokenValidator
{
    private static readonly TimeSpan JwksCacheLifetime = TimeSpan.FromHours(6);
    private readonly IHttpClientFactory httpClientFactory;
    private readonly GoogleOidcOptions options;
    private GoogleJsonWebKeySet? cachedKeys;
    private DateTimeOffset cachedKeysExpiresAt;

    public GoogleIdTokenValidator(IHttpClientFactory httpClientFactory, IConfiguration configuration)
    {
        this.httpClientFactory = httpClientFactory;
        options = configuration.GetSection("GoogleOidc").Get<GoogleOidcOptions>() ?? new GoogleOidcOptions();
    }

    public async Task<GoogleIdentity> ValidateAsync(string idToken, string expectedNonce)
    {
        var parts = idToken.Split('.');
        if (parts.Length != 3)
        {
            throw new SecurityException("Invalid JWT format.");
        }

        var header = DeserializeBase64Url<JwtHeader>(parts[0]);
        if (!string.Equals(header.Algorithm, "RS256", StringComparison.Ordinal))
        {
            throw new SecurityException("Only RS256 Google ID tokens are accepted.");
        }

        if (string.IsNullOrWhiteSpace(header.KeyId))
        {
            throw new SecurityException("Missing key id.");
        }

        var jwks = await GetGoogleKeysAsync();
        var key = jwks.Keys.FirstOrDefault(item => string.Equals(item.KeyId, header.KeyId, StringComparison.Ordinal));
        if (key is null)
        {
            RefreshGoogleKeys();
            jwks = await GetGoogleKeysAsync();
            key = jwks.Keys.FirstOrDefault(item => string.Equals(item.KeyId, header.KeyId, StringComparison.Ordinal));
        }

        if (key is null)
        {
            throw new SecurityException("No matching Google signing key was found.");
        }

        VerifySignature(idToken, key);

        var claims = DeserializeBase64Url<Dictionary<string, JsonElement>>(parts[1]);
        var issuer = GetStringClaim(claims, "iss");
        if (issuer is not ("https://accounts.google.com" or "accounts.google.com"))
        {
            throw new SecurityException("Invalid issuer.");
        }

        var audience = GetStringClaim(claims, "aud");
        if (!string.Equals(audience, options.ClientId, StringComparison.Ordinal))
        {
            throw new SecurityException("Invalid audience.");
        }

        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(GetLongClaim(claims, "exp"));
        if (expiresAt <= DateTimeOffset.UtcNow)
        {
            throw new SecurityException("Token is expired.");
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(GetLongClaim(claims, "iat"));
        if (issuedAt > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw new SecurityException("Token issue time is in the future.");
        }

        var nonce = GetStringClaim(claims, "nonce");
        if (!string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
        {
            throw new SecurityException("Invalid nonce.");
        }

        var subject = GetStringClaim(claims, "sub");
        var email = GetStringClaim(claims, "email");
        var emailVerified = GetBooleanClaim(claims, "email_verified");
        if (string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(email) || !emailVerified)
        {
            throw new SecurityException("Missing required Google identity claims.");
        }

        return new GoogleIdentity(
            subject,
            email,
            emailVerified,
            GetStringClaim(claims, "name"),
            GetStringClaim(claims, "picture"),
            issuer,
            audience,
            expiresAt);
    }

    private async Task<GoogleJsonWebKeySet> GetGoogleKeysAsync()
    {
        if (cachedKeys is not null && cachedKeysExpiresAt > DateTimeOffset.UtcNow)
        {
            return cachedKeys;
        }

        using var http = httpClientFactory.CreateClient();
        var json = await http.GetStringAsync(options.JwksEndpoint);
        cachedKeys = JsonSerializer.Deserialize<GoogleJsonWebKeySet>(
            json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new GoogleJsonWebKeySet([]);
        cachedKeysExpiresAt = DateTimeOffset.UtcNow.Add(JwksCacheLifetime);
        return cachedKeys;
    }

    private void RefreshGoogleKeys()
    {
        cachedKeys = null;
        cachedKeysExpiresAt = DateTimeOffset.MinValue;
    }

    private static void VerifySignature(string jwt, GoogleJsonWebKey key)
    {
        var parts = jwt.Split('.');
        var signedData = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var signature = Base64UrlDecode(parts[2]);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64UrlDecode(key.Modulus),
            Exponent = Base64UrlDecode(key.Exponent)
        });

        var isValid = rsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (!isValid)
        {
            throw new SecurityException("Invalid ID token signature.");
        }
    }

    private static T DeserializeBase64Url<T>(string value)
    {
        var json = Encoding.UTF8.GetString(Base64UrlDecode(value));
        return JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new SecurityException("Invalid JWT JSON.");
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4) % 4, '=');
        return Convert.FromBase64String(normalized);
    }

    private static string? GetStringClaim(Dictionary<string, JsonElement> claims, string name)
    {
        return claims.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static long GetLongClaim(Dictionary<string, JsonElement> claims, string name)
    {
        if (!claims.TryGetValue(name, out var value) || !value.TryGetInt64(out var result))
        {
            throw new SecurityException($"Missing numeric claim: {name}");
        }

        return result;
    }

    private static bool GetBooleanClaim(Dictionary<string, JsonElement> claims, string name)
    {
        if (!claims.TryGetValue(name, out var value))
        {
            return false;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
            _ => false
        };
    }
}

public sealed class ApplicationUserRepository
{
    private readonly ApplicationUsersOptions options;

    public ApplicationUserRepository(IConfiguration configuration)
    {
        options = configuration.GetSection("ApplicationUsers").Get<ApplicationUsersOptions>()
            ?? new ApplicationUsersOptions();
    }

    public ApplicationUser? FindActiveUser(GoogleIdentity googleIdentity)
    {
        return options.Users.FirstOrDefault(user =>
            user.IsActive &&
            ((!string.IsNullOrWhiteSpace(user.GoogleSubject) &&
              string.Equals(user.GoogleSubject, googleIdentity.Subject, StringComparison.Ordinal)) ||
             (!string.IsNullOrWhiteSpace(user.Email) &&
              string.Equals(user.Email, googleIdentity.Email, StringComparison.OrdinalIgnoreCase))));
    }
}

public sealed class AppJwtTokenFactory
{
    private readonly AppJwtOptions options;

    public AppJwtTokenFactory(IConfiguration configuration)
    {
        options = configuration.GetSection("AppJwt").Get<AppJwtOptions>() ?? new AppJwtOptions();
    }

    public AppJwtToken CreateToken(ApplicationUser user, GoogleIdentity googleIdentity)
    {
        if (string.IsNullOrWhiteSpace(options.SigningKey) ||
            options.SigningKey.StartsWith("CHANGE_", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("AppJwt:SigningKey must be configured before issuing application JWTs.");
        }

        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(options.ExpirationMinutes);
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = options.Issuer,
            ["aud"] = options.Audience,
            ["sub"] = user.Id,
            ["email"] = googleIdentity.Email,
            ["name"] = user.DisplayName ?? googleIdentity.Name,
            ["google_sub"] = googleIdentity.Subject,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["roles"] = user.Roles
        };

        var header = new Dictionary<string, object?>
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT"
        };

        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(claims);
        var encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var unsignedToken = $"{encodedHeader}.{encodedPayload}";

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(options.SigningKey));
        var signature = Base64UrlEncode(hmac.ComputeHash(Encoding.ASCII.GetBytes(unsignedToken)));

        return new AppJwtToken($"{unsignedToken}.{signature}", expiresAt, options.Issuer, options.Audience);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

public sealed class SecurityException(string message) : Exception(message);

public sealed class GoogleOidcOptions
{
    public string ClientId { get; init; } = "";
    public string ClientSecret { get; init; } = "";
    public string RedirectUri { get; init; } = "http://localhost:4200/auth/callback";
    public string AuthorizationEndpoint { get; init; } = "https://accounts.google.com/o/oauth2/v2/auth";
    public string TokenEndpoint { get; init; } = "https://oauth2.googleapis.com/token";
    public string JwksEndpoint { get; init; } = "https://www.googleapis.com/oauth2/v3/certs";
    public string[] Scopes { get; init; } = [ "openid", "profile", "email" ];
}

public sealed class AppJwtOptions
{
    public string Issuer { get; init; } = "GoogleOidcPkce.Api";
    public string Audience { get; init; } = "GoogleOidcPkce.Client";
    public string SigningKey { get; init; } = "";
    public int ExpirationMinutes { get; init; } = 60;
}

public sealed class ApplicationUsersOptions
{
    public ApplicationUser[] Users { get; init; } = [];
}

public sealed class ApplicationUser
{
    public string Id { get; init; } = "";
    public string? GoogleSubject { get; init; }
    public string Email { get; init; } = "";
    public string? DisplayName { get; init; }
    public string[] Roles { get; init; } = [];
    public bool IsActive { get; init; }
}

public sealed record GoogleIdentity(
    string Subject,
    string Email,
    bool EmailVerified,
    string? Name,
    string? Picture,
    string? Issuer,
    string? Audience,
    DateTimeOffset ExpiresAt);

public sealed record AuthConfigResponse(
    string ClientId,
    string RedirectUri,
    string AuthorizationEndpoint,
    string[] Scopes);

public sealed record AuthCodeExchangeRequest(
    string Code,
    string CodeVerifier,
    string RedirectUri,
    string Nonce);

public sealed record AuthResult(
    UserProfile Profile,
    TokenMetadata GoogleTokens,
    AppJwtToken ApplicationToken);

public sealed record UserProfile(
    string? Sub,
    string? Name,
    string? Email,
    string? Picture,
    bool EmailVerified,
    string[] Roles);

public sealed record TokenMetadata(
    string? TokenType,
    int ExpiresIn,
    string? Scope,
    bool HasAccessToken);

public sealed record AppJwtToken(
    string AccessToken,
    DateTimeOffset ExpiresAtUtc,
    string Issuer,
    string Audience);

public sealed class GoogleTokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }

    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }
}

public sealed record JwtHeader(
    [property: JsonPropertyName("alg")] string? Algorithm,
    [property: JsonPropertyName("kid")] string? KeyId);

public sealed record GoogleJsonWebKeySet(
    [property: JsonPropertyName("keys")] GoogleJsonWebKey[] Keys);

public sealed record GoogleJsonWebKey(
    [property: JsonPropertyName("kid")] string KeyId,
    [property: JsonPropertyName("n")] string Modulus,
    [property: JsonPropertyName("e")] string Exponent);
