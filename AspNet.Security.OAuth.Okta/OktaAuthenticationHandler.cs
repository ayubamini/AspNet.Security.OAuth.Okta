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
using Microsoft.Extensions.Primitives;
using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

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

        // Step #1 - Start a challenge
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
            var redirectContext = new RedirectContext<OAuthOptions>(
                Context, Scheme, Options,
                properties, authorizationEndpoint);
            await Events.RedirectToAuthorizationEndpoint(redirectContext);

            var location = Context.Response.Headers.Location;
            if (location == StringValues.Empty)
            {
                location = "(not set)";
            }

            var cookie = Context.Response.Headers.SetCookie;
            if (cookie == StringValues.Empty)
            {
                cookie = "(not set)";
            }

            Logger.HandleChallenge(location.ToString(), cookie.ToString());
        }


        // CREATE CHALLENGE URL
        protected override string BuildChallengeUrl([NotNull] AuthenticationProperties properties, [NotNull] string redirectUri)
        {
            var scopeParameter = properties.GetParameter<ICollection<string>>(OAuthChallengeProperties.ScopeKey);
            var scope = scopeParameter != null ? FormatScope(scopeParameter) : FormatScope();

            var parameters = new Dictionary<string, string?>
            {
                ["client_id"] = Options.ClientId,
                ["response_type"] = "code",
                ["scope"] = scope,
                ["redirect_uri"] = redirectUri
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

            //parameters["redirect_uri"] = QueryHelpers.AddQueryString(redirectUri, "state", state);            

            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var query = Request.Query;

            var state = query["state"];
            var properties = Options.StateDataFormat.Unprotect(state);

            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }

            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                var errorDescription = query["error_description"];
                var errorUri = query["error_uri"];
                if (StringValues.Equals(error, "access_denied"))
                {
                    var result = await HandleAccessDeniedErrorAsync(properties);
                    if (!result.None)
                    {
                        return result;
                    }
                    var deniedEx = new Exception("Access was denied by the resource owner or by the remote server.");
                    deniedEx.Data["error"] = error.ToString();
                    deniedEx.Data["error_description"] = errorDescription.ToString();
                    deniedEx.Data["error_uri"] = errorUri.ToString();

                    return HandleRequestResult.Fail(deniedEx, properties);
                }

                var failureMessage = new StringBuilder();
                failureMessage.Append(error);
                if (!StringValues.IsNullOrEmpty(errorDescription))
                {
                    failureMessage.Append(";Description=").Append(errorDescription);
                }
                if (!StringValues.IsNullOrEmpty(errorUri))
                {
                    failureMessage.Append(";Uri=").Append(errorUri);
                }

                var ex = new Exception(failureMessage.ToString());
                ex.Data["error"] = error.ToString();
                ex.Data["error_description"] = errorDescription.ToString();
                ex.Data["error_uri"] = errorUri.ToString();

                return HandleRequestResult.Fail(ex, properties);
            }

            var code = query["code"];

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.", properties);
            }

            var codeExchangeContext = new OAuthCodeExchangeContext(properties, code.ToString(), BuildRedirectUri(Options.CallbackPath));
            using var tokens = await ExchangeCodeAsync(codeExchangeContext);

            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error, properties);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
            }

            var identity = new ClaimsIdentity(ClaimsIssuer);

            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }

                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }

                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens);
            }

            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
            }
        }

        // CHANGE RECEIVED CODE WITH ACCESS_TOKEN
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
            // PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see BuildChallengeUrl
            if (context.Properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier))
            {
                tokenRequestParameters.Add(OAuthConstants.CodeVerifierKey, codeVerifier!);
                context.Properties.Items.Remove(OAuthConstants.CodeVerifierKey);
            }

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters!);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;
            requestMessage.Version = Backchannel.DefaultRequestVersion;
            var response = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);
            var body = await response.Content.ReadAsStringAsync(Context.RequestAborted);

            return response.IsSuccessStatusCode switch
            {
                true => OAuthTokenResponse.Success(JsonDocument.Parse(body)),
                false => PrepareFailedOAuthTokenReponse(response, body)
            };
        }


        private static OAuthTokenResponse PrepareFailedOAuthTokenReponse(HttpResponseMessage response, string body)
        {
            //var errorMessage = $"OAuth token endpoint failure: Status: Unknown Error";
            //return OAuthTokenResponse.Failed(new Exception(errorMessage));

            var exception = OAuthTokenResponse.GetStandardErrorException(JsonDocument.Parse(body));

            if (exception is null)
            {
                var errorMessage = $"OAuth token endpoint failure: Status: {response.StatusCode};Headers: {response.Headers};Body: {body};";
                return OAuthTokenResponse.Failed(new Exception(errorMessage));
            }

            return OAuthTokenResponse.Failed(exception);
        }

        // CREATE_TICKET TO GET USER INFORMATIONS BASED ON SCOPES
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
