using FluentValidation;
using Todos_App.ViewModel;

namespace Todos_App.Validation
{
    public class GetUserRequestValidator : AbstractValidator<GetUserRequest>
    {
        public GetUserRequestValidator()
        {
            RuleFor(request => request.UserName)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Length(6, 100).WithMessage("{PropertyName} phải có ít nhất {MinLength} và không quá {MaxLength} ký tự");

            RuleFor(request => request.FullName)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .Length(0, 255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");

            RuleFor(request => request.Email)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .EmailAddress().WithMessage("{PropertyName} không hợp lệ")
                .Length(0, 255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");

            RuleFor(request => request.AvatarUrl)
                .Length(0, 255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");
        }
    }
}
