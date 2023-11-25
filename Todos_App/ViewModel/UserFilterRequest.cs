using Microsoft.AspNetCore.Mvc;
using Todos_App.Enum;
using Todos_App.Models;

namespace Todos_App.ViewModel
{
    [BindProperties]
    public class UserFilterRequest: FilterRequest
    {
        [BindProperty (Name="type")]
        public UserType? Type { get; set; }

        [BindProperty(Name = "status")]
        public UserStatus? Status { get; set; }
    }
}
