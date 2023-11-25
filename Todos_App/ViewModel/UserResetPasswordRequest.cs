using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UserResetPasswordRequest
    {
        public string NewPassword { get; set; }
        public string CofirmNewPassword { get; set; }
    }
}
