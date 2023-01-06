using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();

var app = builder.Build();

//this is authentication middleware which is kind of same as UseAuthentication middle in dotnetcore
app.Use((context, next) =>
{
    var idp = context.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("set-cookie");
    var authcookie = context.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    //check if there is cookie is set or not
    if (authcookie != null)
    {
        var protectedPayload = authcookie.Split("auth=").Last();
        var payload = protector.Unprotect(protectedPayload);
        var fragment = payload.Split(":");
        var key = fragment[0];
        var value = fragment[1];
        var claims = new List<Claim>
    {
        new Claim(key, value)
    };
        var claimIdentity = new ClaimsIdentity(claims);
        context.User = new ClaimsPrincipal(claimIdentity);
    }
    return next();
});

app.MapGet("/username", (HttpContext context) =>
{
    return context.User?.FindFirst("user")?.Value;
});

app.MapGet("/login", (AuthService auth) =>
{
    auth.SignIn();
    return "ok true";
});

app.MapGet("/", () => "Hello World!");

app.Run();


public class AuthService
{

    private readonly IDataProtectionProvider _idp;
    private readonly IHttpContextAccessor _accessor;
    public AuthService(IDataProtectionProvider idp, IHttpContextAccessor accessor)
    {
        _idp = idp;
        _accessor = accessor;
    }

    public void SignIn()
    {
        var protector = _idp.CreateProtector("set-cookie");
        _accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect("user:sangam")}";
    }
}
