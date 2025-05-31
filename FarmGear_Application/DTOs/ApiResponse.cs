namespace FarmGear_Application.DTOs;

/// <summary>
/// 通用 API 响应 DTO
/// </summary>
public class ApiResponse
{
  /// <summary>
  /// 是否成功
  /// </summary>
  public bool Success { get; set; }

  /// <summary>
  /// 消息
  /// </summary>
  public string Message { get; set; } = string.Empty;
}