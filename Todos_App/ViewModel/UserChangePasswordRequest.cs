using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UserChangePasswordRequest
    {
        public string Password { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmNewPassword { get; set; }
    }
}
