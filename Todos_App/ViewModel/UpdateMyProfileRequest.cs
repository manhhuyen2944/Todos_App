using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UpdateMyProfileRequest
    {
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        public string FullName { get; set; }
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        [EmailAddress(ErrorMessage = "{0} không hợp lệ")]
        public string Email { get; set; }
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        public string AvatarUrl { get; set; }

    }
}
