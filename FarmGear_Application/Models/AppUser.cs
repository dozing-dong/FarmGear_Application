using Microsoft.AspNetCore.Identity;

namespace FarmGear_Application.Models;

/// <summary>
/// 应用程序用户类，继承自IdentityUser
/// </summary>
public class AppUser : IdentityUser
{
  /// <summary>
  /// 用户全名
  /// </summary>
  public string FullName { get; set; } = string.Empty;

  /// <summary>
  /// 用户角色
  /// </summary>
  public string Role { get; set; } = string.Empty;

  /// <summary>
  /// 创建时间
  /// </summary>
  public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

  /// <summary>
  /// 最后登录时间
  /// </summary>
  public DateTime? LastLoginAt { get; set; }

  /// <summary>
  /// 是否激活
  /// </summary>
  public bool IsActive { get; set; } = true;
}