namespace AspNet.Security.OAuth.Okta
{

    public static class OktaAuthenticationDefaults
    {

        public const string AuthenticationScheme = "Okta";

        public static readonly string DisplayName = "Okta";

        public static readonly string Issuer = "https://dev-xxx.okta.com/oauth2/oktaserver";

        public static readonly string CallbackPath = "/redirect";

        public static readonly string AuthorizationEndpoint = "https://dev-xxx.okta.com/oauth2/oktaserver/v1/authorize";

        public static readonly string TokenEndpoint = "https://dev-xxx.okta.com/oauth2/oktaserver/v1/token";

        public static readonly string UserInformationEndpoint = "https://dev-xxx.okta.com/oauth2/oktaserver/v1/userinfo";
    }
}
