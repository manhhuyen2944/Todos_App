using System.ComponentModel.DataAnnotations;

namespace Todos_App.ViewModel
{
    public class UpdateMyProfileRequest
    {
        
        public string FullName { get; set; }
        public string Email { get; set; }
        public string AvatarUrl { get; set; }

    }
}
