using System.ComponentModel.DataAnnotations;

namespace WebApiTemplate.DTO.Auth
{
    public class LoginUserDTO
    {
        [Required(ErrorMessage = "login.email.required")]
        [EmailAddress]
        public required string Email { get; set; }

        [Required(ErrorMessage = "login.password.required")]
        public required string Password { get; set; }
    }
}
