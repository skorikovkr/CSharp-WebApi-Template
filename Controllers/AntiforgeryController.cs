using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApiTemplate.Controllers
{
    [Route("api/[controller]")]
    [Authorize]
    [ApiController]
    public class AntiforgeryController : ControllerBase
    {
        private readonly IAntiforgery _antiforgery;

        public AntiforgeryController(IAntiforgery forgeryService)
        {
            _antiforgery = forgeryService;
        }

        [HttpGet]
        [Route("get-token")] 
        public IActionResult GetToken()
        {
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            HttpContext.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!,
                    new CookieOptions { HttpOnly = false });
            return Ok();
        }
    }
}
