using Microsoft.Extensions.Logging;

namespace AspNet.Security.OAuth.Okta
{
    internal static partial class LoggingExtensions
    {
        [LoggerMessage(1, LogLevel.Debug, "HandleChallenge with Location: {Location}; and Set-Cookie: {Cookie}.", EventName = "HandleChallenge")]
        public static partial void HandleChallenge(this ILogger logger, string location, string cookie);
    }
}
