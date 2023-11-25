using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UserSignUpRequest
    {
        public Guid UserId { get; set; } 
        public string UserName { get; set; }
        public string Email { get; set; } 
        public string Password { get; set; }
        public string CofirmPassword { get; set; }
        public string FullName { get; set; }
        public string AvatarUrl { get; set; }
        public Guid? ModifierId { get; set; }
        public DateTime? LastSignInTime { get; set; }
        public DateTime? ModfiedTime { get; set; }
        public string RecaptchaToken { get; set; }
    }
}
