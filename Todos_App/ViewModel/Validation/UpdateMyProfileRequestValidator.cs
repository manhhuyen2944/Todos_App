using FluentValidation;
using Todos_App.ViewModel;

namespace Todos_App.Validation
{

    public class UpdateMyProfileRequestValidator : AbstractValidator<UpdateMyProfileRequest>
    {
        public UpdateMyProfileRequestValidator()
        {
            RuleFor(request => request.FullName)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .MaximumLength(255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");

            RuleFor(request => request.Email)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .MaximumLength(255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự")
                .EmailAddress().WithMessage("{PropertyName} không hợp lệ");

            RuleFor(request => request.AvatarUrl)
                .MaximumLength(255).WithMessage("{PropertyName} không được quá {MaxLength} ký tự");
        }
    }
}
