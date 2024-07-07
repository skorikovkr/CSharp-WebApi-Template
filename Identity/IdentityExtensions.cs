using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace WebApiTemplate.Identity
{
    public static class IdentityExtensions
    {
        public static IServiceCollection ConfigureIdentityOptions(this IServiceCollection services, IConfiguration config)
        {
            return services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequireDigit =
                    config.GetValue<bool>("Identity:IdentityOptions:Password:RequireDigit");
                options.Password.RequireLowercase =
                    config.GetValue<bool>("Identity:IdentityOptions:Password:RequireLowercase");
                options.Password.RequireNonAlphanumeric =
                    config.GetValue<bool>("Identity:IdentityOptions:Password:RequireNonAlphanumeric");
                options.Password.RequireUppercase =
                    config.GetValue<bool>("Identity:IdentityOptions:Password:RequireUppercase");
                options.Password.RequiredLength =
                    config.GetValue<int>("Identity:IdentityOptions:Password:RequiredLength");
                options.Password.RequiredUniqueChars =
                    config.GetValue<int>("Identity:IdentityOptions:Password:RequiredUniqueChars");
                
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(
                    config.GetValue<int>("Identity:IdentityOptions:Lockout:DefaultLockoutTimeSpan")
                );
                options.Lockout.MaxFailedAccessAttempts =
                    config.GetValue<int>("Identity:IdentityOptions:Lockout:MaxFailedAccessAttempts");
                options.Lockout.AllowedForNewUsers =
                    config.GetValue<bool>("Identity:IdentityOptions:Lockout:AllowedForNewUsers");
                
                var defaultAllowedUserNameCharacters = config.GetValue<string>("Identity:IdentityOptions:User:AllowedUserNameCharacters");
                if (defaultAllowedUserNameCharacters != null)
                {
                    options.User.AllowedUserNameCharacters = defaultAllowedUserNameCharacters;
                }
                options.User.RequireUniqueEmail =
                    config.GetValue<bool>("Identity:IdentityOptions:User:RequireUniqueEmail");
            });
        }

        public static AuthenticationBuilder AddJWTAuthentication(this IServiceCollection services, IConfiguration config)
        {
            var key = config.GetValue<string>("Jwt:Key");
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            return services.AddAuthentication
                (options =>
                    {
                        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                    })
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = true;
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = config.GetValue<string>("Jwt:Issuer"),
                        ValidAudience = config.GetValue<string>("Jwt:Audience"),
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
                    };
                });
        }
    }
}
