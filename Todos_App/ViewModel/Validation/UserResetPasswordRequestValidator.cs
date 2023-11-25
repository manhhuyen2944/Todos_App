using FluentValidation;
using Todos_App.ViewModel;

namespace Todos_App.Validation
{
    public class UserResetPasswordRequestValidator : AbstractValidator<UserResetPasswordRequest>
    {
        public UserResetPasswordRequestValidator()
        {
            RuleFor(request => request.NewPassword)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Length(6, 128).WithMessage("{PropertyName} phải có ít nhất {MinLength} và không quá {MaxLength} ký tự");

            RuleFor(request => request.CofirmNewPassword)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Equal(request => request.NewPassword).WithMessage("Xác nhận mật khẩu mới không khớp");
        }
    }
}
