using System.ComponentModel.DataAnnotations;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace Todos_App.Models
{
    public class UserSubscriptions
    {
        [Key]
        public Guid UserSubscription { get; set; }
        public Guid UserId { get; set; }
        [Column(TypeName = "tinyint")]
        public UserSubscriptiontype Type { get; set; }
        public enum UserSubscriptiontype
        {
            Free = 0,
            Starter = 1,
            Professional = 2,
            Premium = 3,
        }
        [Range(0, double.MaxValue, ErrorMessage = "Giá phải là giá trị không âm.")]
        public decimal Price { get; set; }
        [Range(0, double.MaxValue, ErrorMessage = "Task todo phải là giá trị không âm.")]
        public int? MaximumTodo { get; set; } = null;
        [Column(TypeName = "tinyint")]
        public UserSubscriptiontatus Status { get; set; }
        public enum UserSubscriptiontatus
        {
            Lock = 0,
            Active = 1,
        }
        public DateTime StartTime { get; set; }
        public DateTime? UpComingTime { get; set; } = null;
        public DateTime? EndTime { get; set; } = null;
        public Guid CreatorId { get; set; }
        public DateTime CreateTime { get; set; }
        public Guid? ModifierId { get; set; } = null;
        public DateTime? ModifiedTime { get; set; } = null;
        [ForeignKey("UserId")]
        public  Users User { get; set; }
        [ForeignKey("CreatorId")]
        public  Users Creator { get; set; }
        [ForeignKey("ModifierId")]
        public  Users Modifier { get; set; }
    }
}
