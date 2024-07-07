using System.Security.Claims;

namespace WebApiTemplate.Identity
{
    public interface IJwtGenerator
    {
        string CreateToken(IEnumerable<Claim> claims);
    }
}
