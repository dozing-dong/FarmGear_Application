namespace FarmGear_Application.Configuration;

/// <summary>
/// JWT配置类
/// </summary>
public class JwtSettings
{
  /// <summary>
  /// JWT密钥
  /// </summary>
  public string SecretKey { get; set; } = string.Empty;

  /// <summary>
  /// 发行者
  /// </summary>
  public string Issuer { get; set; } = string.Empty;

  /// <summary>
  /// 接收者
  /// </summary>
  public string Audience { get; set; } = string.Empty;

  /// <summary>
  /// 过期时间（分钟）
  /// </summary>
  public int ExpiryInMinutes { get; set; }
}