using CookieAndJwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var keyManager = new KeyManager();
builder.Services.AddSingleton(keyManager);
builder.Services.AddDbContext<IdentityDbContext>(c => c.UseInMemoryDatabase("my_db"));

//cookie auth is being added by addIdentity
builder.Services.AddIdentity<IdentityUser, IdentityRole>(o =>
    {
        o.User.RequireUniqueEmail = false;
        o.Password.RequireDigit = false;
        o.Password.RequiredLength = 4;
        o.Password.RequireLowercase = false;
        o.Password.RequireUppercase = false;
        o.Password.RequireNonAlphanumeric = false;
    })
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication()
        .AddJwtBearer("jwt", o =>
        {
            o.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false
            };

            o.Events = new()
            {
                OnMessageReceived = ctx =>
                {
                    if(ctx.Request.Query.TryGetValue("t", out var token))
                    {
                        ctx.Token = token;
                    }
                    return Task.CompletedTask;
                }
            };

            o.Configuration = new OpenIdConnectConfiguration()
            {
                SigningKeys =
                {
                    new RsaSecurityKey(keyManager.RsaKey)
                }
            };

            o.MapInboundClaims = false;
        });

builder.Services.AddAuthorization(b =>
{
    b.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, "jwt")
        .Build();
    b.AddPolicy("the_policy", pb => pb
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme, "jwt")
        .RequireClaim("role", "janitor"));
    b.AddPolicy("cookie_policy", pb => pb
        .RequireAuthenticatedUser()
        .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
        .RequireClaim("role", "janitor"));
    b.AddPolicy("token_policy", pb => pb
       .RequireAuthenticatedUser()
       .AddAuthenticationSchemes("jwt")
       .RequireClaim("role", "janitor"));
});

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = await builder.BuildAndSetup();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();

app.MapGet("/", (ClaimsPrincipal user) => user.Claims.Select(x => KeyValuePair.Create(x.Type, x.Value)))
    .RequireAuthorization();

app.MapGet("/secret", () => "secret").RequireAuthorization("the_policy");
app.MapGet("/secret-cookie", () => "cookie secret").RequireAuthorization("cookie_policy");
app.MapGet("/secret-token", () => "token secret").RequireAuthorization("token_policy");

//cookie is created here
app.MapGet("/cookie/sign-in", async (SignInManager<IdentityUser> signInManager) =>
{
    await signInManager.PasswordSignInAsync("test@test.com", "password", false, false);
    return Results.Ok();
});

//jwt token is created here
app.MapGet("/jwt/sign-in", async (
    KeyManager keyManager, 
    IUserClaimsPrincipalFactory<IdentityUser> claimsPrincipalFactory,
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager) =>
{
    var user = await userManager.FindByNameAsync("test@test.com");
    var result = await signInManager.CheckPasswordSignInAsync(user, "password", false);
    var principle = await claimsPrincipalFactory.CreateAsync(user);
    var identity = principle.Identities.First();
    identity.AddClaim(new Claim("arm", "pwd"));
    identity.AddClaim(new Claim("method", "jwt"));
    var handler = new JsonWebTokenHandler();
    var key = new RsaSecurityKey(keyManager.RsaKey);
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "https://locahost:7100",
        Subject = identity,
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
    });

    return token;
});

//jwt example, no user manager/sign in manager (no identity framework)
/*
 */
app.MapGet("/jwt", (KeyManager keyManager) =>
{
    var handler = new JsonWebTokenHandler();
    var key = new RsaSecurityKey(keyManager.RsaKey);
    var token = handler.CreateToken(new SecurityTokenDescriptor()
    {
        Issuer = "https://locahost:7100",
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("sub", Guid.NewGuid().ToString()),
            new Claim("name", "wei")
        }),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
    });

    return token;
});










app.Run();