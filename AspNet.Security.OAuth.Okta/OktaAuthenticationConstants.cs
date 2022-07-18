namespace AspNet.Security.OAuth.Okta
{
    public static class OktaAuthenticationConstants
    {
        public static class Claims
        {
            public const string NameIdentifier = "sub";
            public const string Email = "email";
            public const string BirthDate = "birthdate";
            public const string GivenName = "given_name";
            public const string MiddlName = "middle_name";
            public const string FamilyName = "family_name";
            public const string NickName = "nickname";
            public const string Gender = "gender";
            public const string Picture = "picture";
            public const string PreferredUsername = "preferred_username";
            public const string Profile = "profile";
            public const string UpdatedAt = "updated_at";
            public const string Website = "website";
            public const string ZoneInfo = "zoneinfo";
        }

        public static class Scopes
        {
            public const string OpenId = "openid";
            public const string Email = "openid email";
            public const string Profile = "openid profile";
            public const string Photos = "photos";

        }
    }
}