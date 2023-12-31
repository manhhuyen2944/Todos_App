﻿using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Todos_App.Enum;

namespace Todos_App.Models
{
    public class Users
    {
        [Key]
        public Guid UserId { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "{0} phải có ít nhất {2} và không quá {1} ký tự")]
        public string UserName { get; set; }
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(255, MinimumLength = 6, ErrorMessage = "{0} phải có ít nhất {2} và không quá {1} ký tự")]
        [Column(TypeName = "nvarchar(Max)")]
        public string PasswordHash { get; set; }
        [Column(TypeName = "nvarchar(128)")]
        [DataType(DataType.Password)]
        [StringLength(128, MinimumLength = 6, ErrorMessage = "{0} phải có ít nhất {2} và không quá {1} ký tự")]
        public string PasswordSalt { get; set; }
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        public string FullName { get; set; }
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        [EmailAddress(ErrorMessage = "{0} không hợp lệ")]
        public string Email { get; set; }
        public bool EmailConfirmed { get; set; }
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        public string AvatarUrl { get; set; }
        [Column(TypeName = "tinyint")]
        public UserStatus Status { get; set; } = UserStatus.Active;

        [Column(TypeName = "tinyint")]
        public UserType Type { get; set; } = UserType.User;

        public DateTime? LastSignInTime { get; set; } = null;
        public Guid? ModifierId { get; set; }
        public DateTime? ModfiedTime { get; set; } = null;

        [ForeignKey("ModifierId")]
        [JsonProperty(ItemReferenceLoopHandling = ReferenceLoopHandling.Ignore)]
        public virtual Users Modifier { get; set; }

    }
}
