namespace Todos_App.Services
{
    public interface IRecaptchaService
    {
        Task<bool> VerifyRecaptchaAsync(string recaptchaToken, CancellationToken cancellationToken);
    }
}
