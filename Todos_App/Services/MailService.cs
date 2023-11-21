using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MimeKit;
using Todos_App.Data;
using Todos_App.Models;
using Todos_App.ViewModel;

namespace Todos_App.Services
{
    public class MailService : IMailService
    {
        private readonly MailSettings _mailSettings;
        private readonly ToDosContext _context;

        public MailService(IOptions<MailSettings> mailSettingsOptions, ToDosContext context)
        {
            _mailSettings = mailSettingsOptions.Value;
            _context = context;
        }
        public async Task SendConfirmationEmail(string recipientEmail, string confirmationLink)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == recipientEmail);

            if (user != null)
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress("ToDo_App", "0306201447@caothang.edu.vn"));
                message.To.Add(new MailboxAddress("", recipientEmail));
                message.Subject = "Xác nhận tài khoản đăng ký thành công";
                string fullname = user.FullName;
                var bodyBuilder = new BodyBuilder();
                bodyBuilder.HtmlBody = $"<p>Xin chào {fullname},</p><p>Bạn vừa đăng ký tài khoản thành công. Vui lòng nhấp vào liên kết sau để xác nhận tài khoản:</p><p><a href=\"{confirmationLink}\">{confirmationLink}</a></p>";

                message.Body = bodyBuilder.ToMessageBody();
                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(_mailSettings.Server, _mailSettings.Port, SecureSocketOptions.StartTls);
                    await client.AuthenticateAsync(_mailSettings.UserName, _mailSettings.Password);
                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                }
            }
        }
        public async Task SendResetPasswordEmail(string recipientEmail, string resetPasswordLink)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == recipientEmail);

            try
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress("ToDo_App", "0306201447@caothang.edu.vn"));
                message.To.Add(new MailboxAddress("", recipientEmail));
                message.Subject = "Yêu cầu đặt lại mật khẩu";
                string fullname = user.FullName;
                var bodyBuilder = new BodyBuilder();
                bodyBuilder.HtmlBody = $"<p>Xin chào {fullname},</p>" +
                               "<p>Bạn vừa yêu cầu đặt lại mật khẩu cho tài khoản của mình.</p>" +
                               "<p>Vui lòng nhấp vào liên kết dưới đây để thực hiện đặt lại mật khẩu:</p>" +
                               $"<a href=\"{resetPasswordLink}\">Đặt lại mật khẩu</a>" +
                               "<p>Nếu bạn không yêu cầu đặt lại mật khẩu, hãy bỏ qua email này.</p>" +
                               "<p>Trân trọng,</p>" +
                               "<p>Website todo phân chia công việc thỏa sức</p>";

                message.Body = bodyBuilder.ToMessageBody();
                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(_mailSettings.Server, _mailSettings.Port, SecureSocketOptions.StartTls);
                    await client.AuthenticateAsync(_mailSettings.UserName, _mailSettings.Password);
                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                }
                user.EmailConfirmed = true;
                await _context.SaveChangesAsync();
            }
            catch (Exception)
            {

            }
        }
    }
}
