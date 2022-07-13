using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AspNet.Security.OAuth.Okta
{
    public static class OktaAuthenticationExtensions
    {

        public static AuthenticationBuilder AddOkta([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddOkta(OktaAuthenticationDefaults.AuthenticationScheme, options => { });
        }

        public static AuthenticationBuilder AddOkta(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<OktaAuthenticationOptions> configuration)
        {
            return builder.AddOkta(OktaAuthenticationDefaults.AuthenticationScheme, configuration);
        }

        public static AuthenticationBuilder AddOkta(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme,
            [NotNull] Action<OktaAuthenticationOptions> configuration)
        {
            return builder.AddOkta(scheme, OktaAuthenticationDefaults.DisplayName, configuration);
        }

        public static AuthenticationBuilder AddOkta(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme,
            [CanBeNull] string caption,
            [NotNull] Action<OktaAuthenticationOptions> configuration)
        {
            return builder.AddOAuth<OktaAuthenticationOptions, OktaAuthenticationHandler>(scheme, caption, configuration);
        }
    }
}