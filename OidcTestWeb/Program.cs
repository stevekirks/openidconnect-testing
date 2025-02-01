using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

var configuration = builder.Configuration;
configuration
    .AddJsonFile("appsettings.json")
    .AddJsonFile("appsettings.Development.json", true);

var authority = configuration["OpenIdConnect:Authority"]!;
var clientId = configuration["OpenIdConnect:ClientId"]!;
var clientSecret = configuration["OpenIdConnect:ClientSecret"]!;
var redirectUri = configuration["OpenIdConnect:RedirectUri"]!;
var scopes = configuration["OpenIdConnect:Scopes"]!;
var authorizationEndpoint = $"{authority}/oauth2/v1/authorize";
var tokenEndpoint = $"{authority}/oauth2/v1/token";
var userInfoEndpoint = $"{authority}/oauth2/v1/userinfo";

var app = builder.Build();

// Root Page: Provides links to initiate login with both flows
app.MapGet("/", async (HttpContext context) =>
{
    await context.Response.WriteAsync(@"
        <html>
        <head>
            <title>OIDC Flow Test</title>
        </head>
        <body>
            <h1>Choose Authentication Flow</h1>
            <ul>
                <li><a href='/auth-code'>Login with Authorization Code Flow</a></li>
                <li><a href='/implicit'>Login with Implicit Flow (not recommended)</a></li>
            </ul>
        </body>
        </html>");
});


// Step 1A: Authorization Code Flow - Redirect user to Okta login
app.MapGet("/auth-code", () =>
{
    var authUrl = $"{authorizationEndpoint}?client_id={clientId}&response_type=code&scope={Uri.EscapeDataString(scopes)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&state=xyz";
    Process.Start(new ProcessStartInfo { FileName = authUrl, UseShellExecute = true });

    Console.WriteLine($"Authorization Code Flow call: {authUrl}");
    return "Opening browser for login...";
});

// Step 1B: Implicit Flow - Redirect user to Okta login
app.MapGet("/implicit", () =>
{
    var authUrl = $"{authorizationEndpoint}?client_id={clientId}&response_type=id_token%20token&scope={Uri.EscapeDataString(scopes)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&state=xyz";
    Process.Start(new ProcessStartInfo { FileName = authUrl, UseShellExecute = true });
    
    Console.WriteLine($"Implicit Flow call: {authUrl}");
    return "Opening browser for login...";
});

// Step 2: Handle the OAuth callback for flows
app.MapGet("/authorization-code/callback", async (HttpContext context) =>
{
    var query = context.Request.Query;
    string code = query["code"];
    string error = query["error"];

    if (!string.IsNullOrEmpty(error))
    {
        Console.WriteLine($"Error in authentication: {error}");
        return;
    }

    if (!string.IsNullOrEmpty(code))
    {
        Console.WriteLine($"Authorization Code: {code}");

        using var httpClient = new HttpClient();
        var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        tokenRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        tokenRequest.Content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("client_secret", clientSecret)
        });

        Console.WriteLine($"Making call to token endpoint: {tokenEndpoint}");
        var tokenResponse = await httpClient.SendAsync(tokenRequest);
        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Token Response: {tokenJson}");

        var tokenObj = JsonSerializer.Deserialize<JsonElement>(tokenJson);
        var idToken = tokenObj.GetProperty("id_token").GetString();
        var accessToken = tokenObj.GetProperty("access_token").GetString();

        DecodeAndDisplayClaims(idToken, "ID Token");
        await FetchAndDisplayUserInfo(accessToken);

        // Respond to browser
        await context.Response.WriteAsync("<html><body><h2>Login successful! See details of the claims in the console.<br/>You can close this window.</h2></body></html>");
    }
    else
    {
        // Step 3: If using Implicit Flow, extract tokens from the URL fragment (handled in JavaScript)
        await context.Response.WriteAsync(@"
            <html><body>
            <script>
                const hash = window.location.hash.substring(1);
                const params = new URLSearchParams(hash);
                const idToken = params.get('id_token');
                const accessToken = params.get('access_token') ?? '';
                if (idToken) { 
                    window.location.href = '/implicit-token?id_token=' + idToken + '&access_token=' + accessToken;
                }
            </script>
            <h2>Processing tokens...</h2>
            </body></html>");
    }
});

// Step 4: Handle Implicit Flow token processing
app.MapGet("/implicit-token", async (HttpContext context) =>
{
    var query = context.Request.Query;
    string idToken = query["id_token"];
    string accessToken = query["access_token"];

    if (string.IsNullOrEmpty(idToken))
    {
        await context.Response.WriteAsync("<h2>Error: No ID Token received</h2>");
        return;
    }

    DecodeAndDisplayClaims(idToken, "ID Token (Implicit Flow)");
    if (!string.IsNullOrEmpty(accessToken))
    {
        await FetchAndDisplayUserInfo(accessToken);
    }
    else
    {
        Console.WriteLine("No access token so wont fetch from UserInfo endpoint");
    }

    // Respond to browser
    await context.Response.WriteAsync("<html><body><h2>Login successful! See details of the claims in the console.<br/>You can close this window.</h2></body></html>");

});

void DecodeAndDisplayClaims(string token, string title)
{
    var handler = new JwtSecurityTokenHandler();
    var jwtToken = handler.ReadJwtToken(token);

    Console.WriteLine($"\n{title} Claims:");
    foreach (var claim in jwtToken.Claims)
    {
        Console.WriteLine($"{claim.Type}: {claim.Value}");
    }
}

async Task FetchAndDisplayUserInfo(string accessToken)
{
    Console.WriteLine($"Making call to userInfo endpoint: {userInfoEndpoint}");
    using var httpClient = new HttpClient();
    var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
    userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

    var userInfoResponse = await httpClient.SendAsync(userInfoRequest);
    var userInfoJson = await userInfoResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"\nUserInfo Response: {userInfoJson}");

    var userInfo = JsonSerializer.Deserialize<JsonElement>(userInfoJson);
    if (userInfo.TryGetProperty("groups", out var groups))
    {
        Console.WriteLine("\nGroups:");
        foreach (var group in groups.EnumerateArray())
        {
            Console.WriteLine(group.GetString());
        }
    }
    else
    {
        Console.WriteLine("\nNo groups claim found.");
    }
}

app.Run();
