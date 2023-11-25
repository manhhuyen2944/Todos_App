using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UserSignInRequest
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string RecaptchaToken { get; set; }
    }
}
