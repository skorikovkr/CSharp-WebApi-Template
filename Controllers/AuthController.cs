using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.IdentityModel.Tokens;
using WebApiTemplate.DTO.Auth;
using WebApiTemplate.Exceptions;
using WebApiTemplate.Identity;
using WebApiTemplate.POCO;
using WebApiTemplate.Services;

namespace WebApiTemplate.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly IConfiguration _configuration;

        public AuthController(AuthService authService, IConfiguration configuration)
        {
            _authService = authService;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDTO model)
        {
            try
            {
                await _authService.RegisterUser(model.Email, model.Password, model.Username);
                return NoContent();
            }
            catch (Exception ex)
            {
                if (ex is BadRequestException badRequestException)
                {
                    return BadRequest(new {
                        Message = badRequestException.Message,
                        Errors = badRequestException.Errors
                    });
                }
                else
                    throw;
            }
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginUserDTO model, [FromQuery] bool useCookie = true)
        {
            try
            {
                var tokenPair = await _authService.LoginUser(model.Email, model.Password);
                if (useCookie)
                {
                    SetTokenCookies(tokenPair);
                    return Ok(new
                    {
                        RefreshTokenValidTo = tokenPair.RefreshTokenValidTo,
                        AccessTokenValidTo = tokenPair.AccessTokenValidTo
                    });
                }
                else
                { 
                    return Ok(new { Token = tokenPair });
                }
            }
            catch (Exception ex)
            {
                if (ex is UnauthenticatedException || ex is NotFoundException)
                {
                    return Unauthorized();
                }
                else
                    throw;
            }
        }

        [HttpPost]
        [Route("refresh-tokens")]
        public async Task<IActionResult> RefreshTokens(
            [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] RefreshTokenDTO? model,
            [FromQuery] bool useCookie = true
        )
        {
            try
            {
                string? accessToken = model?.AccessToken;
                string? refreshToken = model?.RefreshToken;
                if (useCookie)
                {
                    if (accessToken == null)
                    {
                        accessToken = HttpContext.Request.Cookies[AuthCookiesKeys.AccessToken];
                    }
                    if (refreshToken == null)
                    {
                        refreshToken = HttpContext.Request.Cookies[AuthCookiesKeys.RefreshToken];
                    }
                }
                if (accessToken == null || refreshToken == null)
                {
                    return BadRequest(new
                    {
                        Message = "Access token or refresh token are null."
                    });
                }
                var tokenPair = await _authService.RefreshTokens(accessToken, refreshToken);
                SetTokenCookies(tokenPair);
                if (useCookie)
                {
                    return Ok(new
                    {
                        RefreshTokenValidTo = tokenPair.RefreshTokenValidTo,
                        AccessTokenValidTo = tokenPair.AccessTokenValidTo
                    });
                }
                else
                {
                    return Ok(tokenPair);
                }
            }
            catch (Exception ex)
            {
                if (ex is BadRequestException badRequestException)
                {
                    return BadRequest(new
                    {
                        Message = badRequestException.Message,
                        Errors = badRequestException.Errors
                    });
                }
                else if (ex is SecurityTokenException || ex is ArgumentException)
                {
                    return BadRequest(new { 
                        Message = "token.invalid"
                    });
                }
                else
                    throw;
            }
        }

        private void SetTokenCookies(TokenPair tokenPair)
        {
            var maxAge = TimeSpan.FromDays(_configuration.GetValue<int>("Jwt:RefreshTokenValidityInDays"));
            // To refresh tokens we need both access (even expired) and refresh tokens.
            // So access token MaxAge should be same as RefreshToken validity.
            // Cookie must be HttpOnly and Secure. This options set in app configuration.
            var options = new CookieOptions
            {
                MaxAge = maxAge
            };
            HttpContext.Response.Cookies.Append(
                AuthCookiesKeys.AccessToken,
                tokenPair.AccessToken,
                options
            );
            HttpContext.Response.Cookies.Append(
                AuthCookiesKeys.RefreshToken,
                tokenPair.RefreshToken,
                options
            );
        }
    }
}
