using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;

namespace AspNet.Security.OAuth.Okta
{

    public class OktaAuthenticationOptions : OAuthOptions
    {
        public OktaAuthenticationOptions()
        {
            ClaimsIssuer = OktaAuthenticationDefaults.Issuer;
            CallbackPath = OktaAuthenticationDefaults.CallbackPath;

            AuthorizationEndpoint = OktaAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = OktaAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = OktaAuthenticationDefaults.UserInformationEndpoint;

            UsePkce = true;

            SaveTokens = true;

            Scope.Add(OktaAuthenticationConstants.Scopes.OpenId);
            Scope.Add(OktaAuthenticationConstants.Scopes.Email);
            Scope.Add(OktaAuthenticationConstants.Scopes.Profile);

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, OktaAuthenticationConstants.Claims.NameIdentifier);
            ClaimActions.MapJsonKey(ClaimTypes.Name, OktaAuthenticationConstants.Claims.Email);
            ClaimActions.MapJsonKey(ClaimTypes.GivenName, OktaAuthenticationConstants.Claims.GivenName);
            ClaimActions.MapJsonKey(ClaimTypes.Surname, OktaAuthenticationConstants.Claims.FamilyName);
            ClaimActions.MapJsonKey(ClaimTypes.Gender, OktaAuthenticationConstants.Claims.Gender);

        }
    }
}