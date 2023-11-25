using FluentValidation;
using Todos_App.ViewModel;

namespace Todos_App.Validation
{
    public class UserUpdateRequestValidator : AbstractValidator<UserUpdateRequest>
    {
        public UserUpdateRequestValidator()
        {
            RuleFor(request => request.FullName)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Length(0, 255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");

            RuleFor(request => request.Email)
                .EmailAddress().WithMessage("{PropertyName} không hợp lệ")
                .Length(0, 255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");

            RuleFor(request => request.AvatarUrl)
                .Length(0, 255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");
        }
    }
}
