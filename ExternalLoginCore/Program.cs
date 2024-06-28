using ExternalLoginCore.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Load configuration from appsettings.json
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Configure Google authentication
builder.Services.AddAuthentication(
    options =>
    {
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddGoogle(googleOptions =>
    {
        googleOptions.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
        googleOptions.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
        googleOptions.CallbackPath = new PathString("/signin-google");
    })
    .AddMicrosoftAccount(microsoftOptions =>
    {
        microsoftOptions.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"]!;
        microsoftOptions.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"]!;
        microsoftOptions.CallbackPath = new PathString("/signin-microsoft");
    })
    .AddTwitter(twitterOptions =>
    {
        twitterOptions.ConsumerKey = builder.Configuration["Authentication:Twitter:ConsumerKey"]!;
        twitterOptions.ConsumerSecret = builder.Configuration["Authentication:Twitter:ConsumerSecret"]!;
        twitterOptions.CallbackPath = new PathString("/signin-twitter");
    })
    .AddFacebook(facebookOptions =>
    {
        facebookOptions.AppId = builder.Configuration["Authentication:Facebook:AppId"]!;
        facebookOptions.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"]!;
        facebookOptions.CallbackPath = new PathString("/signin-facebook");
    })
    .AddGitHub(gitHubOptions =>
    {
        gitHubOptions.ClientId = builder.Configuration["Authentication:GitHub:ClientId"]!;
        gitHubOptions.ClientSecret = builder.Configuration["Authentication:GitHub:ClientSecret"]!;
        gitHubOptions.CallbackPath = new PathString("/signin-github");
    })
    .AddYahoo(yahooOptions =>
    {
        yahooOptions.ClientId = builder.Configuration["Authentication:Yahoo:ClientId"]!;
        yahooOptions.ClientSecret = builder.Configuration["Authentication:Yahoo:ClientSecret"]!;
        yahooOptions.CallbackPath = new PathString("/signin-yahoo");
    })
    .AddLinkedIn(linkedInOptions =>
    {
        linkedInOptions.ClientId = builder.Configuration["Authentication:LinkedIn:ClientId"]!;
        linkedInOptions.ClientSecret = builder.Configuration["Authentication:LinkedIn:ClientSecret"]!;
        linkedInOptions.CallbackPath = new PathString("/signin-linkedin");
    });

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddUserManager<UserManager<IdentityUser>>()
    .AddRoles<IdentityRole>()
    .AddRoleManager<RoleManager<IdentityRole>>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    // User settings.
    options.User.RequireUniqueEmail = true;

    // SignIn settings.
    options.SignIn.RequireConfirmedAccount = true;
    options.SignIn.RequireConfirmedPhoneNumber = false;

    // Lockout settings.
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = false;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

    // Store settings.
    options.Stores.ProtectPersonalData = false;
});

builder.Services.AddControllersWithViews();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/LogOut";
    options.AccessDeniedPath = "/Account/AccessDenied";

    // Cookie settings
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(3);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
