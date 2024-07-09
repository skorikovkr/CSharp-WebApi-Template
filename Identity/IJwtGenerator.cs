using System.Security.Claims;

namespace WebApiTemplate.Identity
{
    public interface IJwtGenerator
    {
        (string DecodedToken, DateTime? Expires) CreateToken(IEnumerable<Claim> claims);
    }
}
