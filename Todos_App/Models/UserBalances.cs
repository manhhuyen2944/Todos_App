using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Todos_App.Models
{
    public class UserBalances
    {
        [Key]
        public Guid UserBalance { get; set; }
        public Guid UserId { get; set; }
        [Range(0, double.MaxValue, ErrorMessage = "Số dư phải là giá trị không âm.")]
        public decimal Balance { get; set; }
        public DateTime? LastTransactionTime { get; set; } = null;
        public byte[] RowVersion { get; set; }
        public DateTime? ModifiedTime { get; set; } = null;
        [ForeignKey("UserId")]
        public  Users Users { get; set; }
    }
}
