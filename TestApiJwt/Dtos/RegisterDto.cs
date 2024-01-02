using System.ComponentModel.DataAnnotations;

namespace TestApiJwt.Dtos
{
    public class RegisterDto
    {
        [StringLength(30)]
        public string firstName { get; set; }
        [StringLength(30)]
        public string LastName { get; set; }
        [StringLength(30)]
        public string Username { get; set; }
        [StringLength(30),EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
