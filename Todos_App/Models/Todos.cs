using System.ComponentModel.DataAnnotations;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations.Schema;

namespace Todos_App.Models
{
    public class Todos
    {
        [Key]
        public Guid TodoId { get; set; }
        public Guid UserId { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(255, ErrorMessage = "{0} không được quá {1} ký tự")]
        public string Title { get; set; }
        [Required(ErrorMessage = "{0} không được bỏ trống")]
        [StringLength(4000, ErrorMessage = "{0} không được quá {1} ký tự")]
        public string Description { get; set; }
        public bool Completed { get; set; }
        public DateTime CreatedTime { get; set; }
        public DateTime? Modified { get; set; } = null;
        [ForeignKey("UserId")]
        public  Users Users { get; set; }
    }
}
