using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Todos_App.Data;
using Todos_App.Models;
using Todos_App.Services;
using Todos_App.ViewModel;

namespace Todos_App.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    public class usersController : ControllerBase
    {
        private readonly ToDosContext _context;
        private readonly IMailService _mailService;
        private readonly IRecaptcharService _recaptcharService;
        private readonly IConfiguration _configuration;

        public usersController(ToDosContext context, IMailService mailService, IRecaptcharService recaptcharService, IConfiguration configuration)
        {
            _context = context;
            _mailService = mailService;
            _recaptcharService = recaptcharService;
            _configuration = configuration;
        }
        #region Sign-up
        [HttpPost("sign-up")]
        public async Task<IActionResult> Signup(UserRegisterRequest request, CancellationToken cancellationToken)
        {

            bool isRecaptchaValid = await _recaptcharService.VerifyRecaptchaAsync(request.RecaptchaToken, cancellationToken).ConfigureAwait(false);
            if (!isRecaptchaValid)
            {
                return BadRequest("Xác minh reCaptCha không thành công.");
            }
            var users = await _context.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName || u.Email == request.Email);
            if (users != null)
            {
                if (users.UserName == request.UserName)
                {
                    return BadRequest("Tài khoản đã tồn tại.");
                }
                if (users.Email == request.Email)
                {
                    return BadRequest("Email đã tồn tại.");
                }
            }
            string passwordSalt = GenerateKey(); // Tạo giá trị salt mới cho mật khẩu
            string passwordHash = ComputeHmacSHA512(request.Password, passwordSalt); // Tính toán hash của mật khẩu
            var userId = Guid.NewGuid();
            var user = new Users
            {
                UserId = userId,
                UserName = request.UserName,
                FullName = request.FullName,
                Email = request.Email,
                AvatarUrl = request.AvatarUrl,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                ModifierId = userId,
                LastSignInTime = DateTime.Now,
                ModfiedTime = DateTime.Now,
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            string token = GenerateToken(userId);
            string confirmationLink = "https://localhost:7174/api/users/confirm-email?userId=" + userId + "&token=" + token;
            await _mailService.SendConfirmationEmail(request.Email, confirmationLink);
            return Ok("Đăng ký tài khoản thành công!");
        }
        #endregion
        #region Sign-in
        [HttpPost("sign-in")]
        public async Task<IActionResult> Signin(UserLoginRequest request, CancellationToken cancellationToken)
        {
            // Kiểm tra xác thực reCaptcha
            bool isRecaptchaValid = await _recaptcharService.VerifyRecaptchaAsync(request.RecaptchaToken, cancellationToken).ConfigureAwait(false);
            if (!isRecaptchaValid)
            {
                return BadRequest("Xác minh reCaptcha không thành công.");
            }

            // Kiểm tra thông tin đăng nhập
            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName);
            if (user == null)
            {
                return BadRequest("Tài khoản không tồn tại.");
            }
            string hashedPassword = ComputeHmacSHA512(request.Password, user.PasswordSalt);
            if (hashedPassword != user.PasswordHash)
            {
                return BadRequest("Mật khẩu không chính xác.");
            }
            if (user.EmailConfirmed == false)
            {
                return BadRequest("Tài khoản chưa được xác minh Email!");
            }
            if (user.Status == UserStatus.Lock)
            {
                return BadRequest("Tài khoản đã bị khóa!");
            }

            // Cập nhật thời gian đăng nhập và lưu vào cơ sở dữ liệu
            user.LastSignInTime = DateTime.Now;
            await _context.SaveChangesAsync();

            // Tạo token JWT
            var tokenString = GenerateToken(user.UserId);
            return Ok(new { Message = $"Xin chào, {user.FullName}!", Token = tokenString });
        }
        #endregion
        #region Change my password
        [HttpPut("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword(UserChangePasswordRequest request)
        {
            // Lấy thông tin người dùng từ token JWT
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null)
            {
                return BadRequest("Không tìm thấy thông tin người dùng.");
            }

            if (!Guid.TryParse(userIdClaim.Value, out Guid userId))
            {
                return BadRequest("Không tìm thấy thông tin người dùng.");
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return BadRequest("Người dùng không tồn tại.");
            }
            string currentPasswordHash = ComputeHmacSHA512(request.Password, user.PasswordSalt);
            if (currentPasswordHash != user.PasswordHash)
            {
                return BadRequest("Mật khẩu cũ không chính xác.");
            }

            // Kiểm tra mật khẩu mới và xác nhận mật khẩu mới
            if (request.NewPassword != request.ConfirmNewPassword)
            {
                return BadRequest("Mật khẩu mới và xác nhận mật khẩu mới không khớp.");
            }

            // Tạo mật khẩu mới và lưu vào cơ sở dữ liệu
            string newPasswordHash = ComputeHmacSHA512(request.NewPassword, user.PasswordSalt);
            user.PasswordHash = newPasswordHash;
            await _context.SaveChangesAsync();

            return Ok("Thay đổi mật khẩu thành công!");
        }
        #endregion
        #region Confirm-email
        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] Guid userId, [FromQuery] string token, [FromServices] IMemoryCache memoryCache)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return BadRequest("Người dùng không tồn tại.");
            }
            if (user.EmailConfirmed)
            {
                return BadRequest("Tài khoản đã được xác nhận Email trước đó.");
            }
            // Kiểm tra tính hợp lệ của token
            bool isTokenValid = VerifyToken(userId, token);
            bool emailConfirmationRequested = memoryCache.GetOrCreate($"EmailConfirmationRequested_{userId}", entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24);
                return true;
            });
            if (!isTokenValid || !emailConfirmationRequested)
            {
                // Kiểm tra xem đã gửi email thông báo trước đó chưa
                bool emailNotificationSent = memoryCache.GetOrCreate($"EmailNotificationSent_{userId}", entry =>
                {
                    entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24);
                    return false;
                });

                if (!emailNotificationSent)
                {
                    string newToken = GenerateToken(userId);
                    string confirmationLink = "https://localhost:7174/api/users/confirm-email?userId=" + userId + "&token=" + newToken;
                    await _mailService.SendConfirmationEmail(user.Email, confirmationLink);

                    // Đánh dấu đã gửi email thông báo
                    memoryCache.Set($"EmailNotificationSent_{userId}", true, TimeSpan.FromHours(24));

                    return BadRequest("Thời gian xác nhận đã hết hạn. Yêu cầu gửi lại email xác nhận thành công!");
                }
                else
                {
                    return BadRequest("Đã gửi email thông báo trước đó. Vui lòng kiểm tra hộp thư đến của bạn.");
                }
            }
            else
            {
                user.EmailConfirmed = true;
                await _context.SaveChangesAsync();
                // Xóa cache
                memoryCache.Remove($"EmailConfirmationRequested_{userId}");
                memoryCache.Remove($"EmailNotificationSent_{userId}");
                return Ok("Xác nhận email thành công!");
            }
        }
        #endregion
        #region Send recover password
        [HttpPost("recover-password")]
        public async Task<IActionResult> RecoverPassword([FromBody] UserRecoverPasswordRequest request, [FromServices] IMemoryCache cacheService)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
            {
                return BadRequest("Email không tồn tại.");
            }
            var userId = user.UserId;
            string resetToken = GenerateToken(userId);
            string cacheKey = "reset_password_" + resetToken;

            if (cacheService.TryGetValue(cacheKey, out DateTime expirationTime))
            {
                if (expirationTime > DateTime.Now)
                {
                    return BadRequest("Bạn đã yêu cầu đặt lại mật khẩu trước đó. Vui lòng kiểm tra email để tìm liên kết đặt lại mật khẩu.");
                }
                else
                {
                    string newToken = GenerateToken(userId);
                    string newCacheKey = "reset_password_" + newToken;
                    expirationTime = DateTime.Now.AddHours(1); // Cập nhật thời gian hết hạn với 1 giờ sau khi tạo token mới
                    string newResetPasswordLink = "https://localhost:7174/api/users/reset-password/" + newToken;
                    await _mailService.SendResetPasswordEmail(user.Email, newResetPasswordLink);

                    // Cập nhật cache với token mới và thời gian hết hạn mới
                    cacheService.Set(newCacheKey, expirationTime, TimeSpan.FromHours(1));

                    // Xóa cacheKey cũ
                    cacheService.Remove(cacheKey);

                    return Ok("Vui lòng kiểm tra email của bạn để đặt lại mật khẩu.");
                }
            }
            cacheService.Set(cacheKey, userId, TimeSpan.FromHours(1));
            string resetPasswordLink = "https://localhost:7174/api/users/reset-password/" + resetToken;
            await _mailService.SendResetPasswordEmail(user.Email, resetPasswordLink);
            return Ok("Vui lòng kiểm tra email của bạn để đặt lại mật khẩu.");
        }
        #endregion
        #region Reset password
        [HttpPut("reset-password/{resetToken}")]
        public async Task<IActionResult> ResetPassword(string resetToken, [FromBody] UserResetPasswordRequest request, [FromServices] IMemoryCache cacheService)
        {
            // Kiểm tra xem reset token có hợp lệ hay không
            string cacheKey = "reset_password_" + resetToken;
            if (!cacheService.TryGetValue(cacheKey, out Guid userId))
            {
                return BadRequest("Mã đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.");
            }

            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return BadRequest("Liên kết đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.");
            }

            // Kiểm tra xem token đã hết hạn hay chưa
            if (cacheService.Get(cacheKey) is DateTime expirationTime && expirationTime <= DateTime.Now)
            {
                return BadRequest("Mã đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.");
            }

            string passwordHash = ComputeHmacSHA512(request.NewPassword, user.PasswordSalt);
            user.PasswordHash = passwordHash;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            cacheService.Remove(cacheKey);

            return Ok("Đổi mật khẩu thành công.");
        }
        #endregion
        #region Get my profile
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userIdString = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(userIdString, out Guid userId))
            {
                return BadRequest("Không tìm thấy thông tin người dùng hoặc giá trị không hợp lệ.");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == userId);

            if (user == null)
            {
                return NotFound("Không tìm thấy thông tin người dùng.");
            }
            var userInfo = new
            {
                FullName = user.FullName,
                Email = user.Email,
                AvatarUrl = user.AvatarUrl
            };
            return Ok(userInfo);
        }
        #endregion
        #region Update my profile
        [HttpPut("me")]
        [Authorize]
        public async Task<IActionResult> UpdateCurrentUser([FromBody] UpdateMyProfileRequest userUpdate)
        {
            var userIdString = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(userIdString, out Guid userId))
            {
                return BadRequest("Không tìm thấy thông tin người dùng hoặc giá trị không hợp lệ.");
            }
            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == userId);
            if (user == null)
            {
                return NotFound("Không tìm thấy thông tin người dùng.");
            }
            user.FullName = userUpdate.FullName;
            user.Email = userUpdate.Email;
            user.AvatarUrl = userUpdate.AvatarUrl;
            _context.SaveChanges();
            return Ok("Thông tin người dùng đã được cập nhật thành công.");
        }
        #endregion
        #region Get user listing
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<UserModel>), StatusCodes.Status200OK)]
        public async Task<IActionResult> GetAllAsnyc([FromQuery] UserFilterRequest userFilterRequest)
        {
            var users = await _context.Users
                            .Where(u =>
                                (string.IsNullOrEmpty(userFilterRequest.Keyword) || (!string.IsNullOrEmpty(userFilterRequest.Keyword) && (u.UserName.Contains(userFilterRequest.Keyword) || u.Email.Contains(userFilterRequest.Keyword)))) &&
                                (!userFilterRequest.Type.HasValue || (userFilterRequest.Type.HasValue && u.Type == userFilterRequest.Type.Value)) &&
                                (!userFilterRequest.Status.HasValue || (userFilterRequest.Status.HasValue && u.Status == userFilterRequest.Status.Value))
                            ).ToListAsync();
            return Ok(users.Select(u => new UserModel()
            {
                UserId = u.UserId,
                UserName = u.UserName,
                Email = u.Email,
                Type = u.Type,
                Status = u.Status
            }));
        }
        #endregion
        #region Create new user
        [HttpPost("create")]
        [Authorize]
        public async Task<IActionResult> CreateUser([FromBody] UserCreateRequest userCreate)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var users = await _context.Users.FirstOrDefaultAsync(u => u.UserName == userCreate.UserName || u.Email == userCreate.Email);
            if (users != null)
            {
                if (users.UserName == userCreate.UserName)
                {
                    return BadRequest("Tài khoản đã tồn tại.");
                }
                if (users.Email == userCreate.Email)
                {
                    return BadRequest("Email đã tồn tại.");
                }
            }
            string passwordSalt = GenerateKey();
            string passwordHash = ComputeHmacSHA512(userCreate.Password, passwordSalt);
            var userId = Guid.NewGuid();
            var newUser = new Users
            {
                UserId = userId,
                UserName = userCreate.UserName,
                FullName = userCreate.FullName,
                Email = userCreate.Email,
                AvatarUrl = userCreate.AvatarUrl,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                ModifierId = userId,
                LastSignInTime = DateTime.Now,
                ModfiedTime = DateTime.Now,
                Type = Enum.Parse<UserType>(userCreate.Type.ToString()),
            };
            // Thêm người dùng mới vào cơ sở dữ liệu
            _context.Users.Add(newUser);
            _context.SaveChanges();
            string token = GenerateToken(userId);
            string confirmationLink = "https://localhost:7174/api/users/confirm-email?userId=" + userId + "&token=" + token;
            await _mailService.SendConfirmationEmail(userCreate.Email, confirmationLink);
            return Ok("Người dùng đã được tạo thành công.");
        }
        #endregion
        #region Update exist user
        [HttpPut("update/{userId:guid}")]
        // [Authorize]
        public async Task<IActionResult> UpdateUser(Guid userId, [FromBody] UserUpdateRequest userUpdate)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
            {
                return NotFound("Người dùng không tồn tại.");
            }

            if (user.Email != userUpdate.Email)
            {
                var existingUserWithEmail = await _context.Users.FirstOrDefaultAsync(u => u.Email == userUpdate.Email);
                if (existingUserWithEmail != null)
                {
                    return BadRequest("Email đã tồn tại.");
                }
            }

            user.FullName = userUpdate.FullName;
            user.Email = userUpdate.Email;
            user.AvatarUrl = userUpdate.AvatarUrl;
            user.Type = Enum.Parse<UserType>(userUpdate.Type.ToString());

            await _context.SaveChangesAsync();

            return Ok("Người dùng đã được cập nhật thành công.");
        }
        #endregion
        public static string ComputeHmacSHA512(string key, string input)
        {
            var hash = new StringBuilder();
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            using (HMACSHA512 hmac = new(keyBytes))
            {
                byte[] hashValue = hmac.ComputeHash(inputBytes);
                foreach (var theByte in hashValue)
                {
                    hash.Append(theByte.ToString("x2"));
                }
            }

            return hash.ToString();
        }
        public static string GenerateKey(int maxSize = 32)
        {
            char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            byte[] data = new byte[1];
            using (RandomNumberGenerator crypto = RandomNumberGenerator.Create())
            {
                crypto.GetNonZeroBytes(data);
                data = new byte[maxSize];
                crypto.GetNonZeroBytes(data);
            }
            StringBuilder result = new(maxSize);
            foreach (byte b in data)
            {
                result.Append(chars[b % chars.Length]);
            }
            return result.ToString();
        }
        private string GenerateToken(Guid userId)
        {
            TokenSettings tokenSettings = _configuration.GetSection("TokenSettings").Get<TokenSettings>();
            string secretKey = tokenSettings.SecretKey;

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: tokenSettings.Issuer,
                audience: tokenSettings.Audience,
                claims: claims,
                expires: DateTime.Now.AddHours(tokenSettings.ExpirationHours),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private bool VerifyToken(Guid userId, string token)
        {
            TokenSettings tokenSettings = _configuration.GetSection("TokenSettings").Get<TokenSettings>();
            string secretKey = tokenSettings.SecretKey;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secretKey);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidIssuer = tokenSettings.Issuer,
                ValidAudience = tokenSettings.Audience,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                SecurityToken validatedToken;
                tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                if (validatedToken is JwtSecurityToken jwtSecurityToken &&
                    jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value == userId.ToString())
                {
                    // Mã token hợp lệ cho userId đã truyền vào
                    return true;
                }
            }
            catch (Exception)
            {
                // Xử lý lỗi khi token không hợp lệ
            }
            return false;
        }
    }
}
