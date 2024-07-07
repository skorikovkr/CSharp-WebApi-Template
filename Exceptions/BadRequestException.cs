using Microsoft.AspNetCore.Identity;

namespace WebApiTemplate.Exceptions
{
    public class BadRequestException : Exception
    {
        public IEnumerable<IdentityError> Errors { get; private set; }

        public BadRequestException(string message) : base(message)
        {
            Errors = new List<IdentityError>();
        }

        public BadRequestException(IEnumerable<IdentityError> errors)
        {
            Errors = errors;
        }
    }
}
