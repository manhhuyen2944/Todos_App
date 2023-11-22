using System.ComponentModel.DataAnnotations;
using Todos_App.Models;
namespace Todos_App.ViewModel
{
    public class UserCreateRequest
    {
        public Guid UserId { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "{0} phải có ít nhất {2} và không quá {1} ký tự")]
        public string UserName { get; set; }
        [Required, EmailAddress]
        public string Email { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(128, MinimumLength = 6, ErrorMessage = "{0} phải có ít nhất {2} và không quá {1} ký tự")]
        public string Password { get; set; }
        [Required, Compare("Password")]
        public string CofirmPassword { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(255, MinimumLength = 10, ErrorMessage = "{0} phải có ít nhất {2} và không quá {1} ký tự")]
        public string FullName { get; set; }
        public string AvatarUrl { get; set; }
        public Guid? ModifierId { get; set; }
        public DateTime? LastSignInTime { get; set; }
        public DateTime? ModfiedTime { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        public UserType Type { get; set; } = UserType.User;
    }
    
}
