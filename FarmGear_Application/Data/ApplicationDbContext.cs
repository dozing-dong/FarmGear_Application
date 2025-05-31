using FarmGear_Application.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FarmGear_Application.Data;

/// <summary>
/// 应用程序数据库上下文
/// </summary>
public class ApplicationDbContext : IdentityDbContext<AppUser>
{
  public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
      : base(options)
  {
  }

  protected override void OnModelCreating(ModelBuilder builder)
  {
    base.OnModelCreating(builder);

    // 配置用户表的索引
    builder.Entity<AppUser>()
        .HasIndex(u => u.Email)
        .IsUnique();

    builder.Entity<AppUser>()
        .HasIndex(u => u.UserName)
        .IsUnique();
  }
}