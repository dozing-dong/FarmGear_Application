using FarmGear_Application.DTOs;
using FarmGear_Application.Models;
using FarmGear_Application.Utils;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace FarmGear_Application.Services;

/// <summary>
/// 认证服务实现
/// </summary>
public class AuthService : IAuthService
{
  private readonly UserManager<AppUser> _userManager;
  private readonly SignInManager<AppUser> _signInManager;
  private readonly JwtTokenGenerator _jwtTokenGenerator;
  private readonly IEmailSender _emailSender;

  public AuthService(
      UserManager<AppUser> userManager,
      SignInManager<AppUser> signInManager,
      JwtTokenGenerator jwtTokenGenerator,
      IEmailSender emailSender)
  {
    _userManager = userManager;
    _signInManager = signInManager;
    _jwtTokenGenerator = jwtTokenGenerator;
    _emailSender = emailSender;
  }

  /// <inheritdoc/>
  public async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
  {
    if (await _userManager.Users.AnyAsync(u => u.UserName == request.Username))
    {
      return new RegisterResponse { Success = false, Message = "Username already exists" };
    }
    if (await _userManager.Users.AnyAsync(u => u.Email == request.Email))
    {
      return new RegisterResponse { Success = false, Message = "Email already exists" };
    }
    var user = new AppUser
    {
      UserName = request.Username,
      Email = request.Email,
      FullName = request.FullName,
      Role = request.Role,
      EmailConfirmed = false,
      IsActive = false
    };
    var result = await _userManager.CreateAsync(user, request.Password);
    if (!result.Succeeded)
    {
      return new RegisterResponse { Success = false, Message = string.Join(", ", result.Errors.Select(e => e.Description)) };
    }
    await _userManager.AddToRoleAsync(user, request.Role);
    await SendEmailConfirmationLinkAsync(user);
    return new RegisterResponse { Success = true, Message = "Registration successful. Please check your email to confirm your account.", UserId = user.Id };
  }

  /// <inheritdoc/>
  public async Task<LoginResponse> LoginAsync(LoginRequest request)
  {
    var user = await _userManager.Users
        .FirstOrDefaultAsync(u => u.UserName == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);
    if (user == null)
    {
      return new LoginResponse { Success = false, Message = "Invalid username or email" };
    }
    if (!user.IsActive)
    {
      return new LoginResponse { Success = false, Message = "Account is not activated. Please check your email to confirm your account." };
    }
    var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
    if (!result.Succeeded)
    {
      return new LoginResponse { Success = false, Message = "Invalid password" };
    }
    user.LastLoginAt = DateTime.UtcNow;
    await _userManager.UpdateAsync(user);
    var token = _jwtTokenGenerator.GenerateToken(user);
    return new LoginResponse { Success = true, Message = "Login successful", Token = token };
  }

  /// <inheritdoc/>
  public async Task<ApiResponse> ConfirmEmailAsync(string userId, string token)
  {
    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
      return new ApiResponse { Success = false, Message = "User not found" };
    }
    var result = await _userManager.ConfirmEmailAsync(user, token);
    if (!result.Succeeded)
    {
      return new ApiResponse { Success = false, Message = string.Join(", ", result.Errors.Select(e => e.Description)) };
    }
    user.IsActive = true;
    await _userManager.UpdateAsync(user);
    return new ApiResponse { Success = true, Message = "Email confirmed successfully" };
  }

  /// <inheritdoc/>
  public async Task<ApiResponse> SendEmailConfirmationLinkAsync(AppUser user)
  {
    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
    var confirmationLink = $"https://your-domain.com/api/auth/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";
    var emailSent = await _emailSender.SendEmailAsync(
        user.Email!,
        "Confirm your email",
        $"Please confirm your account by clicking <a href='{confirmationLink}'>here</a>.");
    return emailSent ?
        new ApiResponse { Success = true, Message = "Confirmation email sent successfully" } :
        new ApiResponse { Success = false, Message = "Failed to send confirmation email" };
  }

  /// <summary>
  /// 检查用户名是否已被使用
  /// </summary>
  public async Task<bool> IsUsernameTakenAsync(string username)
  {
    if (string.IsNullOrWhiteSpace(username))
    {
      return false;
    }

    var user = await _userManager.FindByNameAsync(username);
    return user != null;
  }

  /// <summary>
  /// 检查邮箱是否已被注册
  /// </summary>
  public async Task<bool> IsEmailTakenAsync(string email)
  {
    if (string.IsNullOrWhiteSpace(email))
    {
      return false;
    }

    var user = await _userManager.FindByEmailAsync(email);
    return user != null;
  }
}

/// <summary>
/// 邮件发送接口（用于测试）
/// </summary>
public interface IEmailSender
{
  Task<bool> SendEmailAsync(string email, string subject, string message);
}

/// <summary>
/// 邮件发送实现（用于测试）
/// </summary>
public class EmailSender : IEmailSender
{
  private readonly ILogger<EmailSender> _logger;

  public EmailSender(ILogger<EmailSender> logger)
  {
    _logger = logger;
  }

  public Task<bool> SendEmailAsync(string email, string subject, string message)
  {
    // 在实际环境中，这里应该实现真实的邮件发送逻辑
    // 这里仅用于测试，记录日志
    _logger.LogInformation("Email sent to {Email}: {Subject}\n{Message}", email, subject, message);
    return Task.FromResult(true);
  }
}