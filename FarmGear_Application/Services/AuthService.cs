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
    // 创建一个新的 AppUser 实例，赋值来自前端注册请求
    // 注意：密码不能放在这里，因为它不会被保存为明文，而是交给 Identity 内部逻辑处理
    var user = new AppUser
    {
      UserName = request.Username,           // 用户名（登录用）
      Email = request.Email,                 // 邮箱（后续用于验证）
      FullName = request.FullName,           // 用户全名（自定义字段）
      Role = request.Role,                   // 角色（如 Admin、User，注册时一并提交）
      EmailConfirmed = false,                // 默认未验证邮箱
      IsActive = false                       // 用户初始为未激活状态，可用于启用/禁用用户逻辑
    };

    // 调用 系统自带的 UserManager 的 CreateAsync 方法：创建用户并加密保存密码
    // 内部流程包括：字段验证、密码强度验证、加密密码、保存到数据库（包括将密码写入 PasswordHash 字段）
    //密码加强以后,密码会补充进前面的user实例中,生成一个包含密码的user实例,再进行数据库保存,返回IdentityResult对象
    // 这是异步方法，返回 IdentityResult 对象
    var result = await _userManager.CreateAsync(user, request.Password);

    // 如果用户创建失败（如用户名重复、密码太弱等），返回错误信息给前端
    if (!result.Succeeded)
    {
      return new RegisterResponse
      {
        Success = false,
        Message = string.Join(", ", result.Errors.Select(e => e.Description)) // 将所有错误描述拼接成一句话
      };
    }

    // 用户创建成功后，调用 AddToRoleAsync 把该用户分配到请求的角色中（权限控制用途）
    // 注意：角色名必须在系统中预先存在，否则会失败
    await _userManager.AddToRoleAsync(user, request.Role);

    // 向用户邮箱发送确认链接，通常用于双向验证（防止恶意注册）
    // 内部通常生成 token，并构造验证 URL（如 /confirm-email?token=xxx）发送邮件
    await SendEmailConfirmationLinkAsync(user);

    // 一切正常，构造注册成功的返回结果给前端
    // 包含状态、提示消息以及新用户的唯一标识 ID
    return new RegisterResponse
    {
      Success = true,
      Message = "Registration successful. Please check your email to confirm your account.",
      UserId = user.Id
    };

  }

  /// <summary>
  /// 登录逻辑：支持用户名或邮箱，检查密码、邮箱是否验证、账号是否激活，成功则返回 JWT Token。
  /// </summary>
  /// <param name="request">包含用户名/邮箱和密码的登录请求体</param>
  /// <returns>登录结果响应对象，包含状态、提示信息和 Token（若成功）</returns>
  public async Task<LoginResponse> LoginAsync(LoginRequest request)
  {
    // 1. 根据用户名或邮箱查找用户
    var user = await _userManager.Users
        .FirstOrDefaultAsync(u => u.UserName == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);

    // 2. 如果用户不存在，返回失败提示
    if (user == null)
    {
      return new LoginResponse
      {
        Success = false,
        Message = "Invalid username or email"
      };
    }

    // 3. 检查邮箱是否已经验证（EmailConfirmed 是 Identity 内置字段）
    if (!user.EmailConfirmed)
    {
      return new LoginResponse
      {
        Success = false,
        Message = "Email is not confirmed. Please check your inbox."
      };
    }

    // 4. 检查账号是否已激活（IsActive 是你自定义的控制字段）
    if (!user.IsActive)
    {
      return new LoginResponse
      {
        Success = false,
        Message = "Account is not activated. Please check your email to confirm your account."
      };
    }

    // 5. 验证密码是否正确（不启用锁定机制）
    var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: false);
    if (!result.Succeeded)
    {
      return new LoginResponse
      {
        Success = false,
        Message = "Invalid password"
      };
    }

    // 6. 更新用户的最后登录时间（非强制操作，但利于安全审计）
    user.LastLoginAt = DateTime.UtcNow;
    await _userManager.UpdateAsync(user);

    // 7. 生成 JWT Token（用于身份验证）
    var token = _jwtTokenGenerator.GenerateToken(user);

    // 8. 返回登录成功响应，包含 Token 和提示
    return new LoginResponse
    {
      Success = true,
      Message = "Login successful",
      Token = token
    };
  }


  /// <inheritdoc/>
  /// 确认邮箱, 专有接口会调用这个方法,跟注册并没有关系,实际上是注册以后拦截功能,
  /// 用户注册以后,会调用这个方法,验证邮箱是否有效,如果有效,则通过数据库专有字段的修改激活用户账号,如果无效,则返回错误信息
  /// token 是用户注册以后,系统自动生成的,用于验证邮箱是否有效,
  public async Task<ApiResponse> ConfirmEmailAsync(string userId, string token)
  {
    // 根据 userId 查询用户，如果查不到，返回失败
    var user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
      return new ApiResponse { Success = false, Message = "User not found" };
    }

    // 使用 UserManager 验证邮箱 token 是否有效（自动包含 token 签名、过期等检查）
    var result = await _userManager.ConfirmEmailAsync(user, token);

    // 如果验证失败，返回所有错误信息（如 token 过期、无效）
    if (!result.Succeeded)
    {
      return new ApiResponse
      {
        Success = false,
        Message = string.Join(", ", result.Errors.Select(e => e.Description))
      };
    }

    // 邮箱验证成功后，修改数据库专有字段,激活用户账号
    user.IsActive = true;

    // 更新数据库中的 IsActive 状态
    await _userManager.UpdateAsync(user);

    // 返回成功响应
    return new ApiResponse { Success = true, Message = "Email confirmed successfully" };
  }


  /// <inheritdoc/>
  /// token是用户注册以后,系统自动生成的,用于验证邮箱是否有效
  public async Task<ApiResponse> SendEmailConfirmationLinkAsync(AppUser user)
  {
    // 调用 Identity 的 API 生成邮箱验证 token（包含签名+时间限制）
    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

    // 构造邮箱中的确认链接，注意 token 需要 URL 安全编码
    var confirmationLink = $"https://your-domain.com/api/auth/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

    // 发送邮件（假设 _emailSender 是你封装的邮件服务）
    var emailSent = await _emailSender.SendEmailAsync(
        user.Email!,
        "Confirm your email",
        $"Please confirm your account by clicking <a href='{confirmationLink}'>here</a>.");

    // 根据发送结果返回统一格式
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