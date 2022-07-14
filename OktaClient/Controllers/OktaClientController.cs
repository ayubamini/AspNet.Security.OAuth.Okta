using AspNet.Security.OAuth.Okta;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OktaClient.Extensions;
using System.Threading.Tasks;

namespace OktaClient.Controllers
{
    [AllowAnonymous]
    public class OktaClientController : Controller
    {
       
        [HttpGet("~/signin")]
        public async Task<IActionResult> SignIn() => View("SignIn", await HttpContext.GetExternalProvidersAsync());

        [HttpPost("~/signin")]
        public async Task<IActionResult> SignIn([FromForm] string provider)
        {
            if (string.IsNullOrWhiteSpace(provider))
            {
                return BadRequest();
            }

            if (!await HttpContext.IsProviderSupportedAsync(provider))
            {
                return BadRequest();
            }
            
            return Challenge(new AuthenticationProperties { RedirectUri = "/" }, provider);
        }

        [HttpPost("~/redirect")]
        [HttpGet("~/redirect")]
        public IActionResult Callback()
        {
            var code = Request.Query["code"].ToString();
            var state = Request.Query["state"].ToString();

            var query = new QueryBuilder
            {
                { "code", code },
                { "state", state }
            };
            var url = "/" + query;

            return Redirect($"https://localhost:7209/redirect/{query}");
        }
            

        [HttpGet("~/signout")]
        [HttpPost("~/signout")]
        public IActionResult SignOutCurrentUser()
        {
            return SignOut(new AuthenticationProperties { RedirectUri = "/" },
                CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
