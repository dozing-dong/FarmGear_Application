using FluentValidation;
using FarmGear_Application.DTOs;

namespace FarmGear_Application.Validators;

/// <summary>
/// 登录请求验证器
/// </summary>
public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
  public LoginRequestValidator()
  {
    // 用户名或邮箱验证规则
    RuleFor(x => x.UsernameOrEmail)
        .NotEmpty().WithMessage("Username or email is required")
        .MaximumLength(100).WithMessage("Username or email cannot exceed 100 characters");

    // 密码验证规则
    RuleFor(x => x.Password)
        .NotEmpty().WithMessage("Password is required")
        .MaximumLength(100).WithMessage("Password cannot exceed 100 characters");

    // 可以添加登录尝试次数限制的验证
    // 这需要在 AuthService 中实现具体的逻辑
  }
}