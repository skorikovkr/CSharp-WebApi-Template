using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApiTemplate.Exceptions;
using WebApiTemplate.Identity;
using WebApiTemplate.POCO;

namespace WebApiTemplate.Services
{
    public class AuthService
    {
        private readonly IJwtGenerator _jwtGenerator;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(
            IJwtGenerator jwtGenerator, 
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration
        )
        {
            _jwtGenerator = jwtGenerator;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [AllowAnonymous]
        public async Task<TokenPair> LoginUser(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                throw new NotFoundException("User not found with this email.");
            }
            if (await _userManager.CheckPasswordAsync(user, password))
            {
                var authClaims = await GenerateClaims(user);
                var accessToken = _jwtGenerator.CreateToken(authClaims);
                var refreshToken = GenerateRefreshToken();
                var refreshTokenValidityInDays = _configuration.GetValue<int>("Jwt:RefreshTokenValidityInDays");

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

                await _userManager.UpdateAsync(user);
                return new TokenPair()
                {
                    AccessToken = accessToken.DecodedToken,
                    RefreshToken = refreshToken,
                    RefreshTokenValidTo = user.RefreshTokenExpiryTime,
                    AccessTokenValidTo = accessToken.Expires
                };
            }
            throw new UnauthenticatedException("Wrong credentials.");
        }

        [AllowAnonymous]
        public async Task RegisterUser(string email, string password, string username)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                throw new BadRequestException("User found with this email.");
            }
            user = new()
            {
                Email = email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = username
            };
            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                throw new BadRequestException(result.Errors);
            }
            if (!await _roleManager.RoleExistsAsync(Roles.User))
                await _roleManager.CreateAsync(new IdentityRole(Roles.User));
        }

        [Authorize]
        public async Task<TokenPair> RefreshTokens(string accessToken, string refreshToken)
        {
            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                throw new BadRequestException("Invalid access token.");
            }
            string? email = principal.FindFirstValue(ClaimTypes.Email);
            if (email == null)
            {
                throw new BadRequestException("Invalid access token.");
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                throw new BadRequestException("Invalid refresh token.");
            }

            var refreshTokenValidityInDays = _configuration.GetValue<int>("Jwt:RefreshTokenValidityInDays");
            var authClaims = await GenerateClaims(user);
            var newAccessToken = _jwtGenerator.CreateToken(authClaims);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);
            await _userManager.UpdateAsync(user);

            return new TokenPair()
            { 
                AccessToken = newAccessToken.DecodedToken,
                RefreshToken = newRefreshToken,
                RefreshTokenValidTo = user.RefreshTokenExpiryTime,
                AccessTokenValidTo = newAccessToken.Expires
            };
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            if (String.IsNullOrEmpty(token))
            {
                throw new SecurityTokenException("Invalid token.");
            }
            var key = _configuration["Jwt:Key"];
            if (key == null)
            {
                throw new ArgumentNullException("Secret issuer signing key is null.");
            }
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
                if (securityToken is not JwtSecurityToken jwtSecurityToken)
                    throw new SecurityTokenException("Invalid token.");
                return principal;
            }
            catch (SecurityTokenArgumentException)
            {
                throw new SecurityTokenException("Invalid token.");
            }
        }

        public string GenerateRefreshToken()
        {
            return Guid.NewGuid().ToString();
        }

        public async Task<IEnumerable<Claim>> GenerateClaims(ApplicationUser user)
        {
            if (user.Email == null)
            {
                throw new Exception("User email is null.");
            }
            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim("Id", user.Id)
                };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            return authClaims;
        }
    }
}
