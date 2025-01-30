using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;

// Build the minimal web server
var builder = WebApplication.CreateBuilder(args);

// Load configuration from appsettings.json
var configuration = builder.Configuration;
configuration
    .AddJsonFile("appsettings.json")
    .AddJsonFile("appsettings.Development.json", true);

var oktaDomain = configuration["OpenIdConnect:Domain"];
var clientId = configuration["OpenIdConnect:ClientId"];
var clientSecret = configuration["OpenIdConnect:ClientSecret"];
var redirectUri = configuration["OpenIdConnect:RedirectUri"];
var authorizationEndpoint = $"{oktaDomain}/oauth2/v1/authorize";
var tokenEndpoint = $"{oktaDomain}/oauth2/v1/token";
var userInfoEndpoint = $"{oktaDomain}/oauth2/v1/userinfo";

var app = builder.Build();

// Step 1: Redirect user to Okta login
app.MapGet("/", () =>
{
    string authUrl = $"{authorizationEndpoint}?client_id={clientId}&response_type=code&scope=openid%20profile%20email%20groups&redirect_uri={Uri.EscapeDataString(redirectUri)}&state=xyz";
    Process.Start(new ProcessStartInfo { FileName = authUrl, UseShellExecute = true });

    Console.WriteLine($"Authorization call: {authUrl}");

    return "Opening browser for login...";
});

// Step 2: Handle the OAuth callback and exchange code for tokens
app.MapGet("/authorization-code/callback", async (HttpContext context) =>
{
    var code = context.Request.Query["code"];
    Console.WriteLine($"Authorization Code: {code}");

    // Respond to browser
    await context.Response.WriteAsync("<html><body><h2>Login successful! See details of the claims in the console.<br/>You can close this window.</h2></body></html>");

    // Step 3: Exchange the code for tokens (Access Token + ID Token)
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

    var tokenResponse = await httpClient.SendAsync(tokenRequest);
    var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"Token Response: {tokenJson}");

    // Step 4: Decode the ID Token and extract claims
    var tokenObj = JsonSerializer.Deserialize<JsonElement>(tokenJson);
    var idToken = tokenObj.GetProperty("id_token").GetString();
    var handler = new JwtSecurityTokenHandler();
    var jwtToken = handler.ReadJwtToken(idToken);

    Console.WriteLine("\nID Token Claims:");
    foreach (var claim in jwtToken.Claims)
    {
        Console.WriteLine($"{claim.Type}: {claim.Value}");
    }

    // Step 5: Fetch the UserInfo (includes groups) using the Access Token
    var accessToken = tokenObj.GetProperty("access_token").GetString();
    var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
    userInfoRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

    var userInfoResponse = await httpClient.SendAsync(userInfoRequest);
    var userInfoJson = await userInfoResponse.Content.ReadAsStringAsync();
    Console.WriteLine($"\nUserInfo Response: {userInfoJson}");

    // Step 6: Parse and display the groups claim from UserInfo
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
});

// Run the web server
app.Run();
