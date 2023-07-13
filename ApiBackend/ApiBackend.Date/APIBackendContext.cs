using ApiBackend.Shared;
using Microsoft.EntityFrameworkCore;


namespace ApiBackend.Date
{
    public class APIBackendContext : DbContext
    {
        public APIBackendContext(DbContextOptions options) : base(options) { }

        public DbSet<Client> Clients { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<ProductCategory> ProductCategories { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite();
        }
    }
}
