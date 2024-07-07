using System.Globalization;

namespace WebApiTemplate.Identity
{
    public class ExtractJWTFromCookieToAuthorizationHeaderMiddleware
    {
        private readonly RequestDelegate _next;

        public ExtractJWTFromCookieToAuthorizationHeaderMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var token = context.Request.Cookies[AuthCookiesKeys.AccessToken];
            if (!string.IsNullOrEmpty(token))
                context.Request.Headers["Authorization"] = "Bearer " + token;

            await _next(context);
        }
    }
}
