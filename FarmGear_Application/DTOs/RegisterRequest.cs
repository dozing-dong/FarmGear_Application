using System.ComponentModel.DataAnnotations;

namespace FarmGear_Application.DTOs;

/// <summary>
/// 注册请求 DTO
/// </summary>
public class RegisterRequest
{
  /// <summary>
  /// 用户名
  /// </summary>
  [Required(ErrorMessage = "Username is required")]
  [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
  public string Username { get; set; } = string.Empty;

  /// <summary>
  /// 邮箱
  /// </summary>
  [Required(ErrorMessage = "Email is required")]
  [EmailAddress(ErrorMessage = "Invalid email address")]
  public string Email { get; set; } = string.Empty;

  /// <summary>
  /// 密码
  /// </summary>
  [Required(ErrorMessage = "Password is required")]
  [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
  public string Password { get; set; } = string.Empty;

  /// <summary>
  /// 确认密码（可选，但需与 Password 一致）
  /// </summary>
  [Compare("Password", ErrorMessage = "Passwords do not match")]
  public string ConfirmPassword { get; set; } = string.Empty;

  /// <summary>
  /// 全名（可选）
  /// </summary>
  [StringLength(100, ErrorMessage = "Full name cannot exceed 100 characters")]
  public string FullName { get; set; } = string.Empty;

  /// <summary>
  /// 用户角色
  /// </summary>
  [Required(ErrorMessage = "Role is required")]
  public string Role { get; set; } = string.Empty;
}