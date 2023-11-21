using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UserResetPasswordRequest
    {
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(128, MinimumLength = 6, ErrorMessage = "{0} phải có ít nhất {2} và không quá {1} ký tự")]
        public string NewPassword { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [Compare("NewPassword", ErrorMessage = "Xác nhận mật khẩu mới không khớp")]
        public string CofirmNewPassword { get; set; }
    }
}
