namespace FarmGear_Application.DTOs;

/// <summary>
/// 登录响应 DTO
/// </summary>
public class LoginResponse
{
  /// <summary>
  /// 是否成功
  /// </summary>
  public bool Success { get; set; }

  /// <summary>
  /// 消息
  /// </summary>
  public string Message { get; set; } = string.Empty;

  /// <summary>
  /// JWT Token（登录成功时返回）
  /// </summary>
  public string? Token { get; set; }
}