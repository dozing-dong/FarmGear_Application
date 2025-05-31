using FarmGear_Application.DTOs;
using FarmGear_Application.Models;

namespace FarmGear_Application.Services;

/// <summary>
/// 认证服务接口
/// </summary>
public interface IAuthService
{
  /// <summary>
  /// 注册新用户
  /// </summary>
  /// <param name="request">注册请求</param>
  /// <returns>注册响应</returns>
  Task<RegisterResponse> RegisterAsync(RegisterRequest request);

  /// <summary>
  /// 用户登录
  /// </summary>
  /// <param name="request">登录请求</param>
  /// <returns>登录响应</returns>
  Task<LoginResponse> LoginAsync(LoginRequest request);

  /// <summary>
  /// 确认邮箱
  /// </summary>
  /// <param name="userId">用户ID</param>
  /// <param name="token">确认Token</param>
  /// <returns>通用响应</returns>
  Task<ApiResponse> ConfirmEmailAsync(string userId, string token);

  /// <summary>
  /// 发送邮箱确认链接
  /// </summary>
  /// <param name="user">用户信息</param>
  /// <returns>通用响应</returns>
  Task<ApiResponse> SendEmailConfirmationLinkAsync(AppUser user);

  /// <summary>
  /// 检查用户名是否已被使用
  /// </summary>
  Task<bool> IsUsernameTakenAsync(string username);

  /// <summary>
  /// 检查邮箱是否已被注册
  /// </summary>
  Task<bool> IsEmailTakenAsync(string email);
}