using Microsoft.EntityFrameworkCore;
using Todos_App.Models;

namespace Todos_App.Data
{
  
    public class ToDosContext : DbContext
    {
        public ToDosContext(DbContextOptions<ToDosContext> options) : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UserSubscriptions>()
                .HasOne(u => u.User)
                .WithMany()
                .HasForeignKey(u => u.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<UserSubscriptions>()
                .HasOne(u => u.Creator)
                .WithMany()
                .HasForeignKey(u => u.CreatorId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<UserSubscriptions>()
                .HasOne(u => u.Modifier)
                .WithMany()
                .HasForeignKey(u => u.ModifierId)
                .OnDelete(DeleteBehavior.Restrict);
        }
        public DbSet<Users> Users { get; set; }
        public DbSet<Todos> Todos { get; set; }
        public DbSet<UserSubscriptions> UserSubscriptions { get; set; }
        public DbSet<UserTransactions> UserTransactions { get; set; }
        public DbSet<UserBalances> UserBalances { get; set; }

    }
}
