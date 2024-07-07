using System.ComponentModel.DataAnnotations;

namespace WebApiTemplate.DTO.Auth
{
    public class RegisterUserDTO
    {
        [Required(ErrorMessage = "register.username.required")]
        public required string Username { get; set; }

        [EmailAddress(ErrorMessage = "register.email.invalid")]
        [Required(ErrorMessage = "register.email.required")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "register.password.required")]
        public required string Password { get; set; }
    }
}
