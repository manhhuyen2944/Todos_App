namespace Todos_App.Services
{
    public interface IMailService
    {
        Task SendConfirmationEmail(string recipientEmail, string confirmationLink);
        Task SendResetPasswordEmail(string recipientEmail, string confirmationLink);
    }
}
