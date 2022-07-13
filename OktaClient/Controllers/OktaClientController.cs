using AspNet.Security.OAuth.Okta;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
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
            ViewBag.Code = Request.Query["code"];
            ViewBag.State = Request.Query["state"];

            var code = Request.Query["code"];
            var state = Request.Query["state"];

            return View();
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
