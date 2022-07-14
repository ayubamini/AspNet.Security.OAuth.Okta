using AspNet.Security.OAuth.Okta;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace OktaClient
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.LoginPath = "/signin";
                options.LogoutPath = "/signout";
            })
            .AddOkta(options =>
            {
                options.ClientId = Configuration["OAuth:Okta:ClientId"];
                options.ClientSecret = Configuration["OAuth:Okta:ClientSecret"];
            })
            .AddOAuth("Okta2", options =>
            {
                options.ClientId = Configuration["OAuth:Okta:ClientId"];
                options.ClientSecret = Configuration["OAuth:Okta:ClientSecret"];
                options.CallbackPath = "/redirect";
                options.AuthorizationEndpoint = Configuration["OAuth:Okta:AuthorizationEndpoint"];
                options.TokenEndpoint = Configuration["OAuth:Okta:TokenEndpoint"];
                options.UserInformationEndpoint = Configuration["OAuth:Okta:UserInformationEndpoint"];
                options.Scope.Add("openid");
            });

            services.AddMvc();

            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
