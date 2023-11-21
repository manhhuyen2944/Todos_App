using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UserRecoverPasswordRequest
    {
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        [EmailAddress(ErrorMessage = "{0} không hợp lệ")]
        public string Email { get; set; }
    }
}
