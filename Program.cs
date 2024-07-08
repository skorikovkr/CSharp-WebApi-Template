using Microsoft.AspNetCore.CookiePolicy;
using WebApiTemplate.Identity;
using WebApiTemplate.Services;
using Microsoft.AspNetCore.Identity;

namespace WebApiTemplate
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Identity services
            builder.Services.AddSqlite<ApplicationIdentityDbContext>(builder.Configuration.GetValue<string>("ConnectionStrings:ApplicationIdentityDb"));
            builder.Services.AddJWTAuthentication(builder.Configuration);
            builder.Services.AddIdentityCore<ApplicationUser>(options => {
                options.SignIn.RequireConfirmedAccount = false;
            })
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<ApplicationIdentityDbContext>();
            builder.Services.ConfigureIdentityOptions(builder.Configuration);
            builder.Services.AddScoped<IJwtGenerator, JwtGenerator>();
            builder.Services.AddScoped<AuthService>();

            builder.Services.AddMvc();

            builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(
                    policy =>
                    {
                        policy.WithOrigins(builder.Configuration.GetSection("Cors:Origins")?.Get<string[]>() ?? [])
                              .AllowAnyHeader()
                              .AllowCredentials()
                              .AllowAnyMethod();
                    }
                );
            });

            var app = builder.Build();

            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                var context = services.GetRequiredService<ApplicationIdentityDbContext>();
                SeedData.Initialize(services).Wait();
            }

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseCors();

            app.UseCookiePolicy(new CookiePolicyOptions
            {
                MinimumSameSitePolicy = SameSiteMode.Strict,
                HttpOnly = HttpOnlyPolicy.Always,
                Secure = CookieSecurePolicy.Always
            });

            app.UseStaticFiles();

            app.UseMiddleware<ExtractJWTFromCookieToAuthorizationHeaderMiddleware>();
            app.Use(async (context, next) =>
            {
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                context.Response.Headers["X-Xss-Protection"] = "1";
                context.Response.Headers["X-Frame-Options"] = "DENY";
                context.Response.Headers["Content-Security-Policy"] = "default-src 'none'";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                await next();
            });

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
