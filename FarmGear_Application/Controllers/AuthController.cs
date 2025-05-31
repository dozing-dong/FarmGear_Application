using FarmGear_Application.DTOs;
using FarmGear_Application.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FarmGear_Application.Controllers;

/// <summary>
/// 认证控制器
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
  private readonly IAuthService _authService;
  private readonly ILogger<AuthController> _logger;

  public AuthController(IAuthService authService, ILogger<AuthController> logger)
  {
    _authService = authService;
    _logger = logger;
  }

  /// <summary>
  /// 用户注册
  /// </summary>
  /// <param name="request">注册请求</param>
  /// <returns>注册响应</returns>
  [HttpPost("register")]
  [ProducesResponseType(typeof(RegisterResponse), StatusCodes.Status200OK)]
  [ProducesResponseType(typeof(RegisterResponse), StatusCodes.Status400BadRequest)]
  public async Task<IActionResult> Register([FromBody] RegisterRequest request)
  {
    try
    {
      var response = await _authService.RegisterAsync(request);
      if (!response.Success)
        return BadRequest(response);
      return Ok(response);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error occurred during registration");
      return StatusCode(500, new RegisterResponse { Success = false, Message = "An error occurred during registration" });
    }
  }

  /// <summary>
  /// 用户登录
  /// </summary>
  /// <param name="request">登录请求</param>
  /// <returns>登录响应</returns>
  [HttpPost("login")]
  [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
  [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status400BadRequest)]
  public async Task<IActionResult> Login([FromBody] LoginRequest request)
  {
    try
    {
      var response = await _authService.LoginAsync(request);
      if (!response.Success)
        return BadRequest(response);
      return Ok(response);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error occurred during login");
      return StatusCode(500, new LoginResponse { Success = false, Message = "An error occurred during login" });
    }
  }

  /// <summary>
  /// 用户登出
  /// </summary>
  /// <returns>通用响应</returns>
  [HttpPost("logout")]
  [Authorize]
  [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
  public IActionResult Logout()
  {
    // 由于使用JWT，服务器端不需要维护会话状态
    // 客户端需要自行清除Token
    return Ok(new ApiResponse { Success = true, Message = "Logout successful" });
  }

  /// <summary>
  /// 确认邮箱
  /// </summary>
  /// <param name="userId">用户ID</param>
  /// <param name="token">确认Token</param>
  /// <returns>通用响应</returns>
  [HttpGet("confirm-email")]
  [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
  [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status400BadRequest)]
  public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
  {
    try
    {
      var response = await _authService.ConfirmEmailAsync(userId, token);
      if (!response.Success)
        return BadRequest(response);
      return Ok(response);
    }
    catch (Exception ex)
    {
      _logger.LogError(ex, "Error occurred during email confirmation");
      return StatusCode(500, new ApiResponse { Success = false, Message = "An error occurred during email confirmation" });
    }
  }
}