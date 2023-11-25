using FluentValidation;
using Todos_App.ViewModel;

namespace Todos_App.Validation
{
    public class UserCreateRequestValidator : AbstractValidator<UserCreateRequest>
    {
        public UserCreateRequestValidator()
        {
            RuleFor(request => request.UserName)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Length(6, 100).WithMessage("{PropertyName} phải có ít nhất {MinLength} và không quá {MaxLength} ký tự");

            RuleFor(request => request.Email)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .EmailAddress().WithMessage("{PropertyName} không hợp lệ");

            RuleFor(request => request.Password)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Length(6, 128).WithMessage("{PropertyName} phải có ít nhất {MinLength} và không quá {MaxLength} ký tự");

            RuleFor(request => request.CofirmPassword)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Equal(request => request.Password).WithMessage("Xác nhận mật khẩu không khớp");

            RuleFor(request => request.FullName)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Length(10, 255).WithMessage("{PropertyName} phải có ít nhất {MinLength} và không quá {MaxLength} ký tự");

            RuleFor(request => request.Type)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống");
        }
    }
}
