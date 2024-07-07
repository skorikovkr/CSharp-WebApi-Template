using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

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
            return Ok();
        }
    }
}
