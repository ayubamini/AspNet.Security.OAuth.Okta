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
            services.AddMvc();

            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = "Okta";
            //})
            //    .AddCookie()
            //    .AddOAuth("Okta2", options =>
            //    {
            //        options.ClientId = Configuration["OAuth:Okta:ClientId"];
            //        options.ClientSecret = Configuration["OAuth:Okta:ClientSecret"];
            //        options.CallbackPath = new PathString("/redirect");
            //        options.Scope.Add("openid");

            //        options.AuthorizationEndpoint = "https://dev-26827217.okta.com/oauth2/oktaserver/v1/authorize";
            //        options.TokenEndpoint = "https://dev-26827217.okta.com/oauth2/oktaserver/v1/token";
            //        options.UserInformationEndpoint = "https://dev-26827217.okta.com/oauth2/userinfo.openid";

            //        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            //        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");

            //        options.Events = new OAuthEvents
            //        {
            //            OnCreatingTicket = async context =>
            //            {
            //                var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
            //                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            //                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

            //                var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
            //                response.EnsureSuccessStatusCode();

            //                var user = JObject.Parse(await response.Content.ReadAsStringAsync());

            //                //context.RunClaimActions(user);
            //            }
            //        };
            //    });

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

            app.UseAuthentication();
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
