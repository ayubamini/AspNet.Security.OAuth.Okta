# AspNet.Security.OAuth.Okta
`AspNet.Security.OAuth.Okta` is library include collection of security middlewares to authorize users based on `OAuth 2.0` and OpenId Connect protocol in your application. You use it for ASP.NET Core application to support external authentication provider like Microsoft, Google, Facebook and etc. However, there is some differences, because `Microsoft` already added these famouse companies and for others you need override some methods that iheritted from Microsoft `OAuthHandler` class.

As you mentioned, This project is based on Okta and for others you should be change something in all classes for support your favorite non-famouse companies like Walmart, Costco and etc. Just need to customize `OktaAuthenticationHandler.cs` a little bit on the other classes.

After that, make sure you Added Authentication block inside `Startup.cs` of your ASP.NET Core Applications.

```csharp
public void ConfigureServices(IServiceCollection services)
{

    services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));
    services.AddControllersWithViews();


    // Your external provider ------------------------------------------------
    services.AddAuthentication()
    .AddOkta(options =>
    {
        options.ClientId = Configuration["OAuth:Okta:ClientId"];
        options.ClientSecret = Configuration["OAuth:Okta:ClientSecret"];
    });
    //-------------------------------------------------------------------------

    services.AddMvc();

    services.AddControllersWithViews();
}
```

And this configuration in `appsettings.json` file (You will get this values when you register in developer.okta.com):

```csharp
 "OAuth": {
    "Okta": {
      "ClientId": "{YOUR_CLIENT_ID}",
      "ClientSecret": "{YOUR_CLIENT_SECRET}"
    }
  }
```

And in the last no need to add extra controller for this reason and you can use `Microsoft` Scaffolding Identity ExternalLogin service.

For more information about OAuth 2.0 please, use this link https://oauth.net/2
