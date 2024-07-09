using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace WebApiTemplate.Identity
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using (var context = new ApplicationIdentityDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationIdentityDbContext>>()))
            {
                var config = serviceProvider.GetRequiredService<IConfiguration>();
                var pass = config["SeedData:FirstAdmin:Password"];
                var email = config["SeedData:FirstAdmin:Email"];
                if (pass != null && email != null)
                {
                    var username = config["SeedData:FirstAdmin:Username"] ?? email;
                    var adminID = await EnsureUser(serviceProvider, username, pass, email);
                    var result = await EnsureRole(serviceProvider, adminID, Roles.Admin);
                    if (result != null && !result.Succeeded)
                    {
                        var firstError = result.Errors.First();
                        throw new Exception(firstError.Code + firstError.Description);
                    }
                    result = await EnsureRole(serviceProvider, adminID, Roles.User);
                    if (result != null && !result.Succeeded)
                    {
                        var firstError = result.Errors.First();
                        throw new Exception(firstError.Code + firstError.Description);
                    }
                }
            }
        }

        private static async Task<string> EnsureUser(
            IServiceProvider serviceProvider,
            string username,
            string pass, 
            string email
        )
        {
            var userManager = serviceProvider.GetService<UserManager<ApplicationUser>>();
            if (userManager == null)
            {
                throw new ArgumentNullException($"Dependency '{nameof(userManager)}' not found in service provider.");
            }
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    Email = email,
                    UserName = username,
                    EmailConfirmed = false
                };
                await userManager.CreateAsync(user, pass);
            }
            if (user == null)
            {
                throw new Exception("Cannot create user.");
            }
            return user.Id;
        }

        private static async Task<IdentityResult?> EnsureRole(IServiceProvider serviceProvider, string uid, string role)
        {
            var roleManager = serviceProvider.GetService<RoleManager<IdentityRole>>();
            if (roleManager == null)
            {
                throw new ArgumentNullException($"Dependency '{nameof(roleManager)}' not found in service provider.");
            }

            IdentityResult? IR = null;
            if (!await roleManager.RoleExistsAsync(role))
            {
                IR = await roleManager.CreateAsync(new IdentityRole(role));
            }

            var userManager = serviceProvider.GetService<UserManager<ApplicationUser>>();
            if (userManager == null)
            {
                throw new ArgumentNullException($"Dependency '{nameof(userManager)}' not found in service provider.");
            }

            var user = await userManager.FindByIdAsync(uid);
            if (user == null)
            {
                throw new Exception("Cannot assign role to user.");
            }
            if (!await userManager.IsInRoleAsync(user, role))
            {
                IR = await userManager.AddToRoleAsync(user, role);
            }

            return IR;
        }
    }
}
