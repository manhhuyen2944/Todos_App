using Newtonsoft.Json;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Todos_App.Enum;

namespace Todos_App.Models
{
    public class UserSubscriptions
    {
        [Key]
        public Guid UserSubscription { get; set; }
        public Guid UserId { get; set; }
        [Column(TypeName = "tinyint")]
        public UserSubScriptionType Type { get; set; }
        [Range(0, double.MaxValue, ErrorMessage = "Giá phải là giá trị không âm.")]
        public decimal Price { get; set; }
        [Range(0, double.MaxValue, ErrorMessage = "Task todo phải là giá trị không âm.")]
        public int? MaximumTodo { get; set; } = null;
        [Column(TypeName = "tinyint")]
        public UserSubScriptionStatus Status { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime? UpComingTime { get; set; } = null;
        public DateTime? EndTime { get; set; } = null;
        public Guid CreatorId { get; set; }
        public DateTime CreateTime { get; set; }
        public Guid? ModifierId { get; set; } = null;
        public DateTime? ModifiedTime { get; set; } = null;
        [ForeignKey("UserId")]
        [JsonProperty(ItemReferenceLoopHandling = ReferenceLoopHandling.Ignore)]
        public virtual Users User { get; set; }
        [ForeignKey("CreatorId")]
        [JsonProperty(ItemReferenceLoopHandling = ReferenceLoopHandling.Ignore)]
        public virtual Users Creator { get; set; }
        [ForeignKey("ModifierId")]
        [JsonProperty(ItemReferenceLoopHandling = ReferenceLoopHandling.Ignore)]
        public virtual Users Modifier { get; set; }
    }
}
