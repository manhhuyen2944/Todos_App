using FluentValidation;
using Todos_App.ViewModel;

namespace Todos_App.Validation
{
    public class UserRecoverPasswordRequestValidator : AbstractValidator<UserRecoverPasswordRequest>
    {
        public UserRecoverPasswordRequestValidator()
        {
            RuleFor(request => request.Email)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống")
                .EmailAddress().WithMessage("{PropertyName} không hợp lệ");
        }
    }
}
