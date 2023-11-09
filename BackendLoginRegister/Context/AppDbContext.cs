using BackendLoginRegister.Models;
using Microsoft.EntityFrameworkCore;

namespace BackendLoginRegister.Context
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options):base(options)
        {
            
        }

        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder) //take entity to .net core to sql table
        {
            modelBuilder.Entity<User>().ToTable("users");
        }
    }
}
