using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using JetBrains.Annotations;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace AspNet.Security.OAuth.Okta
{
    public partial class OktaAuthenticationHandler : OAuthHandler<OktaAuthenticationOptions>
    {
        public OktaAuthenticationHandler(
            [NotNull] IOptionsMonitor<OktaAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {

        }

        // STEP #1: CREATE CHALLENGE URL
        protected override string BuildChallengeUrl([NotNull] AuthenticationProperties properties, [NotNull] string redirectUri)
        {
            var scopeParameter = properties.GetParameter<ICollection<string>>(OAuthChallengeProperties.ScopeKey);
            var scope = scopeParameter != null ? FormatScope(scopeParameter) : FormatScope();

            var parameters = new Dictionary<string, string?>
            {
                ["client_id"] = Options.ClientId,
                ["response_type"] = "code",
                ["scope"] = scope
            };

            if (Options.UsePkce)
            {
                //var bytes = RandomNumberGenerator.GetInt32(256 / 8);
                var bytes = BitConverter.GetBytes(256 / 8);
                var codeVerifier = WebEncoders.Base64UrlEncode(bytes);

                // Store this for use during the code redemption.
                properties.Items.Add(OAuthConstants.CodeVerifierKey, codeVerifier);

                var challengeBytes = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
                var codeChallenge = WebEncoders.Base64UrlEncode(challengeBytes);

                parameters[OAuthConstants.CodeChallengeKey] = codeChallenge;
                parameters[OAuthConstants.CodeChallengeMethodKey] = OAuthConstants.CodeChallengeMethodS256;
            }

            var state = Options.StateDataFormat.Protect(properties);
            parameters["state"] = state;
            parameters["redirect_uri"] = redirectUri;

            //parameters["redirect_uri"] = QueryHelpers.AddQueryString(redirectUri, "state", state);            

            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);
        }

        // STEP #2: CHANGE RECEIVED CODE WITH ACCESS_TOKEN
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync([NotNull] OAuthCodeExchangeContext context)
        {
            var tokenRequestParameters = new Dictionary<string, string?>()
            {
                ["client_id"] = Options.ClientId,
                ["client_secret"] = Options.ClientSecret,
                ["redirect_uri"] = context.RedirectUri,
                ["code"] = context.Code,
                ["grant_type"] = "authorization_code"
            };

            // Add CodeVerify to tokenRequestParameters
            if (context.Properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier))
            {
                tokenRequestParameters.Add(OAuthConstants.CodeVerifierKey, codeVerifier);
                context.Properties.Items.Remove(OAuthConstants.CodeVerifierKey);
            }

            var endpoint = QueryHelpers.AddQueryString(Options.TokenEndpoint, tokenRequestParameters);

            using var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-www-form-urlencoded"));
            request.Content = new FormUrlEncodedContent(tokenRequestParameters);

            using var response = await Backchannel.SendAsync(request, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                await Log.ExchangeCodeErrorAsync(Logger, response, Context.RequestAborted);
                return OAuthTokenResponse.Failed(new System.Exception("An error occurred while retrieving an OAuth token."));
            }

            var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted));

            //var accessToken = payload.RootElement.GetProperty("access_token").GetString("token");
            //var token = new
            //{
            //    access_token = accessToken,
            //    token_type = string.Empty,
            //    refresh_token = string.Empty,
            //    expires_in = string.Empty,
            //};
            //return OAuthTokenResponse.Success(JsonSerializer.SerializeToDocument(token));

            return OAuthTokenResponse.Success(payload);
        }

        // STEP #3: CREATE_TICKET TO GET USER INFORMATIONS BASED ON SCOPES
        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            [NotNull] ClaimsIdentity identity,
            [NotNull] AuthenticationProperties properties,
            [NotNull] OAuthTokenResponse tokens)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            using var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                await Log.UserProfileErrorAsync(Logger, response, Context.RequestAborted);
                throw new HttpRequestException("An error occurred while retrieving the user profile.");
            }

            using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted));

            var principal = new ClaimsPrincipal(identity);
            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement.GetProperty("data"));
            context.RunClaimActions();

            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
        }

        // Log methos to show error messages
        private static partial class Log
        {
            internal static async Task UserProfileErrorAsync(ILogger logger, HttpResponseMessage response, CancellationToken cancellationToken)
            {
                UserProfileError(
                    logger,
                    response.StatusCode,
                    response.Headers.ToString(),
                    await response.Content.ReadAsStringAsync(cancellationToken));
            }

            internal static async Task ExchangeCodeErrorAsync(ILogger logger, HttpResponseMessage response, CancellationToken cancellationToken)
            {
                ExchangeCodeError(
                    logger,
                    response.StatusCode,
                    response.Headers.ToString(),
                    await response.Content.ReadAsStringAsync(cancellationToken));
            }

            [LoggerMessage(1, LogLevel.Error, "An error occurred while retrieving the user profile: the remote server returned a {Status} response with the following payload: {Headers} {Body}.")]
            private static partial void UserProfileError(
                ILogger logger,
                System.Net.HttpStatusCode status,
                string headers,
                string body);

            [LoggerMessage(2, LogLevel.Error, "An error occurred while retrieving an OAuth token: the remote server returned a {Status} response with the following payload: {Headers} {Body}.")]
            private static partial void ExchangeCodeError(
            ILogger logger,
            System.Net.HttpStatusCode status,
            string headers,
            string body);
        }

    }
}