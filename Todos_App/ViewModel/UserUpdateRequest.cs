using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using Todos_App.Models;
using Todos_App.Enum;

namespace Todos_App.ViewModel
{
    public class UserUpdateRequest
    {
        
        public string FullName { get; set; }
        public string Email { get; set; }
        public string AvatarUrl { get; set; }
        public UserType Type { get; set; } = UserType.User;
    }
}
