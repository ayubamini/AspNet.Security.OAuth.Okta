using Microsoft.AspNetCore.Authentication;
using System.Text;
using System.Text.Json;

namespace AspNet.Security.OAuth.Okta
{
    public class OAuthTokenResponse : IDisposable
    {
        private OAuthTokenResponse(JsonDocument response)
        {
            Response = response;
            var root = response.RootElement;
            AccessToken = root.GetString("access_token");
            TokenType = root.GetString("token_type");
            RefreshToken = root.GetString("refresh_token");
            ExpiresIn = root.GetString("expires_in");
            Error = GetStandardErrorException(response);
        }

        private OAuthTokenResponse(Exception error)
        {
            Error = error;
        }

        public static OAuthTokenResponse Success(JsonDocument response)
        {
            return new OAuthTokenResponse(response);
        }

        public static OAuthTokenResponse Failed(Exception error)
        {
            return new OAuthTokenResponse(error);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            Response?.Dispose();
        }

        public JsonDocument? Response { get; set; }

        public string? AccessToken { get; set; }

        public string? TokenType { get; set; }

        public string? RefreshToken { get; set; }

        public string? ExpiresIn { get; set; }

        public Exception? Error { get; set; }

        internal static Exception? GetStandardErrorException(JsonDocument response)
        {
            var root = response.RootElement;
            var error = root.GetString("error");

            if (error is null)
            {
                return null;
            }

            var result = new StringBuilder("OAuth token endpoint failure: ");
            result.Append(error);

            if (root.TryGetProperty("error_description", out var errorDescription))
            {
                result.Append(";Description=");
                result.Append(errorDescription);
            }

            if (root.TryGetProperty("error_uri", out var errorUri))
            {
                result.Append(";Uri=");
                result.Append(errorUri);
            }

            var exception = new Exception(result.ToString());
            exception.Data["error"] = error.ToString();
            exception.Data["error_description"] = errorDescription.ToString();
            exception.Data["error_uri"] = errorUri.ToString();

            return exception;
        }
    }
}


