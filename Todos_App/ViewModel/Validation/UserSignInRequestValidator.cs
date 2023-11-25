using FluentValidation;
using Todos_App.ViewModel;

namespace Todos_App.Validation
{
    public class UserSignInRequestValidator : AbstractValidator<UserSignInRequest>
    {
        public UserSignInRequestValidator()
        {
            RuleFor(request => request.UserName)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống");

            RuleFor(request => request.Password)
                .NotEmpty().WithMessage("{PropertyName} không được bỏ trống");
            RuleFor(request => request.RecaptchaToken)
               .NotEmpty().WithMessage("{PropertyName} không được bỏ trống");
        }
    }
}
