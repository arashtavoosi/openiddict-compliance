using Microsoft.EntityFrameworkCore;

namespace OpenIddict.Compliance.Models
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions options)
            : base(options) { }
    }
}
