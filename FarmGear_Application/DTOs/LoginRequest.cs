using System.ComponentModel.DataAnnotations;

namespace FarmGear_Application.DTOs;

/// <summary>
/// 登录请求 DTO
/// </summary>
public class LoginRequest
{
  /// <summary>
  /// 用户名或邮箱（必填）
  /// </summary>
  [Required(ErrorMessage = "Username or email is required")]
  public string UsernameOrEmail { get; set; } = string.Empty;

  /// <summary>
  /// 密码（必填）
  /// </summary>
  [Required(ErrorMessage = "Password is required")]
  public string Password { get; set; } = string.Empty;

  /// <summary>
  /// 记住我（可选，默认为 false）
  /// </summary>
  public bool RememberMe { get; set; }
}