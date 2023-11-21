using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UserLoginRequest
    {
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        public string Password { get; set; }
        public string RecaptchaToken { get; set; }
    }
}
