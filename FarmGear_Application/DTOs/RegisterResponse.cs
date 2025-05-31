namespace FarmGear_Application.DTOs;

/// <summary>
/// 注册响应 DTO
/// </summary>
public class RegisterResponse
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
  /// 用户ID（注册成功时返回）
  /// </summary>
  public string? UserId { get; set; }
}