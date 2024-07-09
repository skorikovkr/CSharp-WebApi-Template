using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace WebApiTemplate.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [AutoValidateAntiforgeryToken]
    public class TestController : ControllerBase
    {
        [HttpPost]
        [Authorize]
        public IActionResult Get()
        {
            return Ok(HttpContext.User.FindFirstValue("Id"));
        }
    }
}
