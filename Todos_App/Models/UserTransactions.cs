using Newtonsoft.Json;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Todos_App.Enum;

namespace Todos_App.Models
{
    public class UserTransactions
    {
        [Key]
        public Guid UserTransactionId { get; set; }
        public Guid UserId { get; set; }
        [DisplayName("Số lượng")]
        [Range(0, double.MaxValue, ErrorMessage = "Số lượng phải là giá trị không âm.")]
        public decimal Amount { get; set; }
        [DisplayName("Số dư cũ")]
        [Range(0, double.MaxValue, ErrorMessage = "Số dư cũ phải là giá trị không âm.")]
        public decimal OldBalance { get; set; }
        [DisplayName("Số dư mới")]
        [Range(0, double.MaxValue, ErrorMessage = "Số dư mới phải là giá trị không âm.")]
        public decimal NewBalance { get; set; }
        [DisplayName("Số thời gian")]
        public DateTime Time { get; set; }
        [DisplayName("Thời gian hoàn thành")]
        public DateTime? CompletedTime { get; set; } = null;
        [Column(TypeName = "tinyint")]
        public UserTransactionType Type { get; set; }
        [DisplayName("Tùy chọn 1")]
        [StringLength(255, ErrorMessage = "Không được quá {1} ký tự")]
        public string Option1 { get; set; }
        [DisplayName("Tùy chọn 2")]
        [MaxLength]
        public string Option2 { get; set; }
        [ForeignKey("UserId")]
        [JsonProperty(ItemReferenceLoopHandling = ReferenceLoopHandling.Ignore)]
        public virtual Users Users { get; set; }
    }
}
