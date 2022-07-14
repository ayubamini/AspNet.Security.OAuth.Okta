using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OktaClient.Data;

[assembly: HostingStartup(typeof(OktaClient.Areas.Identity.IdentityHostingStartup))]
namespace OktaClient.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) => {
                services.AddDbContext<OktaClientContext>(options =>
                    options.UseSqlServer(
                        context.Configuration.GetConnectionString("OktaClientContextConnection")));

                services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                    .AddEntityFrameworkStores<OktaClientContext>();
            });
        }
    }
}
