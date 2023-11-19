using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace CookieAndJwt
{
    public static class ApplicationBuilderExtension
    {
        public static async Task<WebApplication> BuildAndSetup(this WebApplicationBuilder builder)
        {
            var app = builder.Build();
            using (var scope = app.Services.CreateScope())
            {
                var usrMgr = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
                var user = new IdentityUser() { UserName = "test@test.com", Email = "test@test.com" };
                await usrMgr.CreateAsync(user, password: "password");
                await usrMgr.AddClaimAsync(user, new Claim("role", "janitor"));
            }

            return app;
        }
    }
}
