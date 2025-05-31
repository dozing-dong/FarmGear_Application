using System.ComponentModel.DataAnnotations;

namespace FarmGear_Application.Validators;

/// <summary>
/// 密码强度验证特性
/// </summary>
public class PasswordStrengthAttribute : ValidationAttribute
{
  protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
  {
    if (value == null)
    {
      return new ValidationResult("Password is required");
    }

    var password = value.ToString();
    if (string.IsNullOrEmpty(password))
    {
      return new ValidationResult("Password is required");
    }

    var errors = new List<string>();

    if (password.Length < 8)
    {
      errors.Add("Password must be at least 8 characters");
    }

    if (!password.Any(char.IsUpper))
    {
      errors.Add("Password must contain at least one uppercase letter");
    }

    if (!password.Any(char.IsLower))
    {
      errors.Add("Password must contain at least one lowercase letter");
    }

    if (!password.Any(char.IsDigit))
    {
      errors.Add("Password must contain at least one number");
    }

    if (!password.Any(c => !char.IsLetterOrDigit(c)))
    {
      errors.Add("Password must contain at least one special character");
    }

    if (errors.Any())
    {
      return new ValidationResult(string.Join("; ", errors));
    }

    return ValidationResult.Success;
  }
}