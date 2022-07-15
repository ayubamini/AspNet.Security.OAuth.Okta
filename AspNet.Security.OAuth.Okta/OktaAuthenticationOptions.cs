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

            Scope.Add(OktaAuthenticationConstants.Scopes.OpenId);
            Scope.Add(OktaAuthenticationConstants.Scopes.Photos);
            //Scope.Add(OktaAuthenticationConstants.Scopes.OpenIdEmail);
            //Scope.Add(OktaAuthenticationConstants.Scopes.OpenIdProfile);

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, OktaAuthenticationConstants.Claims.Sub);

            //ClaimActions.MapJsonKey(ClaimTypes.Email, OktaAuthenticationConstants.Claims.Email);
            //ClaimActions.MapJsonKey(ClaimTypes.DateOfBirth, OktaAuthenticationConstants.Claims.BirthDate);
            //ClaimActions.MapJsonKey(ClaimTypes.GivenName, OktaAuthenticationConstants.Claims.GivenName);
            //ClaimActions.MapJsonKey(ClaimTypes.Surname, OktaAuthenticationConstants.Claims.FamilyName);
            //ClaimActions.MapJsonKey(ClaimTypes.Gender, OktaAuthenticationConstants.Claims.Gender);
            //ClaimActions.MapJsonKey(ClaimTypes.Name, OktaAuthenticationConstants.Claims.NickName);
            //ClaimActions.MapJsonKey(ClaimTypes.Webpage, OktaAuthenticationConstants.Claims.Website);

            //Events = new OAuthEvents
            //{
            //    OnRedirectToAuthorizationEndpoint = async context => { await context.HttpContext.ChallengeAsync(AuthorizationEndpoint); },
            //    OnCreatingTicket = async context => { await context.HttpContext.ChallengeAsync(); }
            //};
        }

        public override void Validate()
        {
            base.Validate();
        }

        public ISet<string> Fields { get; } = new HashSet<string>
        {
            "email",
            "name",
            "user_id"
        };
    }
}