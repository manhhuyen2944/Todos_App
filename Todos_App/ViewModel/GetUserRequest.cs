using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using Todos_App.Enum;

namespace Todos_App.ViewModel
{
    public class GetUserRequest
    {
        public Guid UserId { get; set; }
        public string UserName { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public string AvatarUrl { get; set; }
        public UserStatus Status { get; set; }
        public UserType Type { get; set; } 
        public DateTime? LastSignInTime { get; set; } = null;
        public Guid? ModifierId { get; set; }
        public DateTime? ModfiedTime { get; set; } = null;
    }
}
