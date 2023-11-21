namespace Todos_App.Services
{
    public interface IRecaptcharService
    {
        Task<bool> VerifyRecaptchaAsync(string recaptchaToken, CancellationToken cancellationToken);
    }
}
