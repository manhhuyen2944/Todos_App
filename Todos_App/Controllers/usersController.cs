using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Todos_App.Data;
using Todos_App.Enum;
using Todos_App.Helper;
using Todos_App.Models;
using Todos_App.Services;
using Todos_App.ViewModel;
namespace Todos_App.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class usersController : BaseApiController
    {
        private readonly ToDosContext _context;
        private readonly IMailService _mailService;
        private readonly IRecaptcharService _recaptcharService;
        private readonly IConfiguration _configuration;
        private readonly IValidator<UserSignUpRequest> _userSignUpRequest;
        private readonly IValidator<UserSignInRequest> _userSignInRequest;
        private readonly IValidator<UpdateMyProfileRequest> _updateMyProfileRequest;
        private readonly IValidator<UserChangePasswordRequest> _userChangePasswordRequest;
        private readonly IValidator<UserCreateRequest> _userCreateRequest;
        private readonly IValidator<UserRecoverPasswordRequest> _userRecoverPasswordRequest;
        private readonly IValidator<UserResetPasswordRequest> _userResetPasswordRequest;
        private readonly IValidator<UserUpdateRequest> _userUpdateRequest;

        public usersController(ToDosContext context, IMailService mailService,
            IRecaptcharService recaptcharService, IConfiguration configuration,
            IValidator<UserSignUpRequest> userSignUpRequest, IValidator<UserSignInRequest> userSignInRequest,
            IValidator<UpdateMyProfileRequest> updateMyProfileRequest, IValidator<UserChangePasswordRequest> userChangePasswordRequest,
            IValidator<UserCreateRequest> userCreateRequest, IValidator<UserRecoverPasswordRequest> userRecoverPasswordRequest,
            IValidator<UserResetPasswordRequest> userResetPasswordRequest, IValidator<UserUpdateRequest> serUpdateRequest)
        {
            _context = context;
            _mailService = mailService;
            _recaptcharService = recaptcharService;
            _configuration = configuration;
            _userSignUpRequest = userSignUpRequest;
            _userSignInRequest = userSignInRequest;

            _updateMyProfileRequest = updateMyProfileRequest;
            _userChangePasswordRequest = userChangePasswordRequest;
            _userCreateRequest = userCreateRequest;
            _userRecoverPasswordRequest = userRecoverPasswordRequest;
            _userResetPasswordRequest = userResetPasswordRequest;
            _userUpdateRequest = serUpdateRequest;
        }
        #region Sign-up
        [HttpPost("sign-up")]
        [AllowAnonymous]
        public async Task<IActionResult> Signup(UserSignUpRequest request, CancellationToken cancellationToken)
        {
            var validationResult = await _userSignUpRequest.ValidateAsync(request, cancellationToken);
            if (!validationResult.IsValid)
            {
                return BadRequest(validationResult.Errors);
            }
            bool isRecaptchaValid = await _recaptcharService.VerifyRecaptchaAsync(request.RecaptchaToken, cancellationToken).ConfigureAwait(false);
            if (!isRecaptchaValid)
            {
                return BadRequest("Xác minh reCaptCha không thành công.");
            }
            var users = await _context.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName || u.Email == request.Email);
            if (users != null)
            {
                if (users.UserName == request.UserName || users.Email == request.Email)
                {
                    return BadRequest("Tài khoản hoặc Email đã tồn tại.");
                }
            }
            string passwordSalt = HashValue.GenerateKey(); // Tạo giá trị salt mới cho mật khẩu
            string passwordHash = HashValue.ComputeHmacSHA512(request.Password, passwordSalt); // Tính toán hash của mật khẩu
            var userId = Guid.NewGuid();
            var user = new Users
            {
                UserId = userId,
                UserName = request.UserName,
                FullName = CultureInfo.CurrentCulture.TextInfo.ToTitleCase(request.FullName.ToLower()),
                Email = request.Email,
                AvatarUrl = request.AvatarUrl,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                ModifierId = userId,
                LastSignInTime = DateTime.Now,
                ModfiedTime = DateTime.Now,
            };
            _context.Users.Add(user);
            var userSubscription = new UserSubscriptions
            {
                UserSubscription = Guid.NewGuid(),
                UserId = userId,
                Type = UserSubScriptionType.Free,
                Price = 0,
                MaximumTodo = 10,
                Status = UserSubScriptionStatus.Cancelled,
                StartTime = DateTime.Now,
                CreateTime = DateTime.Now,
                CreatorId = userId,
                ModifierId = userId,
            };
            _context.UserSubscriptions.Add(userSubscription);
            await _context.SaveChangesAsync();
            string token = GenerateToken(userId);
            string confirmationEmailUrl = _configuration.GetValue<string>("AppSettings:ConfirmationEmailUrl");
            string confirmationLink = confirmationEmailUrl + userId + "&token=" + token;
            await _mailService.SendConfirmationEmail(request.Email, confirmationLink);
            return Ok("Đăng ký tài khoản thành công!");
        }
        #endregion
        #region Sign-in
        [HttpPost("sign-in")]
        [AllowAnonymous]
        public async Task<IActionResult> Signin(UserSignInRequest request, CancellationToken cancellationToken)
        {
            var validationResult = await _userSignInRequest.ValidateAsync(request, cancellationToken);
            if (!validationResult.IsValid)
            {
                // Xử lý khi validation không thành công
                return BadRequest(validationResult.Errors);
            }
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
            string hashedPassword = Helper.HashValue.ComputeHmacSHA512(request.Password, user.PasswordSalt);
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
            user.LastSignInTime = DateTime.Now;
            await _context.SaveChangesAsync();

            // Tạo token JWT
            var tokenString = GenerateToken(user.UserId);
            return Ok(new { Message = $"Xin chào, {user.FullName}!", Token = tokenString });
        }
        #endregion
        #region Change my password
        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword(UserChangePasswordRequest request)
        {
            var validationResult = await _userChangePasswordRequest.ValidateAsync(request);
            if (!validationResult.IsValid)
            {
                return BadRequest(validationResult.Errors);
            }
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
            if (string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(validationResult.Errors);
            }

            string currentPasswordHash = Helper.HashValue.ComputeHmacSHA512(request.Password, user.PasswordSalt);
            if (currentPasswordHash != user.PasswordHash)
            {
                return BadRequest("Mật khẩu cũ không chính xác");
            }
            if (request.NewPassword != request.ConfirmNewPassword)
            {
                return BadRequest(validationResult.Errors);
            }
            string newPasswordHash = Helper.HashValue.ComputeHmacSHA512(request.NewPassword, user.PasswordSalt);
            user.PasswordHash = newPasswordHash;
            await _context.SaveChangesAsync();

            return Ok("Thay đổi mật khẩu thành công!");
        }
        #endregion
        #region Confirm-email
        [HttpGet("confirm-email")]
        [AllowAnonymous]
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
                    string confirmationEmailUrl = _configuration.GetValue<string>("AppSettings:ConfirmationEmailUrl");
                    string confirmationLink = confirmationEmailUrl + userId + "&token=" + token;
                    await _mailService.SendConfirmationEmail(user.Email, confirmationLink);
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
        [AllowAnonymous]
        public async Task<IActionResult> RecoverPassword([FromBody] UserRecoverPasswordRequest request, [FromServices] IMemoryCache cacheService)
        {
            var validationResult = await _userRecoverPasswordRequest.ValidateAsync(request);
            if (!validationResult.IsValid)
            {
                // Xử lý khi validation không thành công
                return BadRequest(validationResult.Errors);
            }
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
            {
                return BadRequest("Email không tồn tại.");
            }
            var userId = user.UserId;
            string resetToken = GenerateToken(userId);
            string cacheKey = "reset_password_" + resetToken;
            string resetPasswordEmailUrl = _configuration.GetValue<string>("AppSettings:ResetPasswordEmail");
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
                    expirationTime = DateTime.Now.AddHours(1);

                    string newResetPasswordLink = resetPasswordEmailUrl + newToken;
                    await _mailService.SendResetPasswordEmail(user.Email, newResetPasswordLink);
                    cacheService.Set(newCacheKey, expirationTime, TimeSpan.FromHours(1));
                    cacheService.Remove(cacheKey);
                    return Ok("Vui lòng kiểm tra email của bạn để đặt lại mật khẩu.");
                }
            }
            cacheService.Set(cacheKey, userId, TimeSpan.FromHours(1));
            string resetPasswordLink = resetPasswordEmailUrl + resetToken;
            await _mailService.SendResetPasswordEmail(user.Email, resetPasswordLink);
            return Ok("Vui lòng kiểm tra email của bạn để đặt lại mật khẩu.");
        }
        //public async Task<IActionResult> RecoverPassword([FromBody] UserRecoverPasswordRequest request, [FromServices] IRedisCache cacheService)
        //{
        //    var validationResult = await _userRecoverPasswordRequest.ValidateAsync(request);
        //    if (!validationResult.IsValid)
        //    {
        //        // Xử lý khi validation không thành công
        //        return BadRequest(validationResult.Errors);
        //    }

        //    var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        //    if (user == null)
        //    {
        //        return BadRequest("Email không tồn tại.");
        //    }

        //    var userId = user.UserId;
        //    string resetToken = Guid.NewGuid().ToString();
        //    string cacheKey = "reset_password_" + resetToken;

        //    if (await cacheService.GetAsync(cacheKey) != null)
        //    {
        //        return BadRequest("Bạn đã yêu cầu đặt lại mật khẩu trước đó. Vui lòng kiểm tra email để tìm liên kết đặt lại mật khẩu.");
        //    }
        //    else
        //    {
        //        string newToken = Guid.NewGuid().ToString();
        //        string newCacheKey = "reset_password_" + newToken;
        //        var expirationTime = DateTime.Now.AddHours(1);
        //        string newResetPasswordLink = "https://localhost:7174/api/users/reset-password/" + newToken;
        //        await _mailService.SendResetPasswordEmail(user.Email, newResetPasswordLink);
        //        await cacheService.SetAsync(newCacheKey, userId, expirationTime - DateTime.Now);
        //        await cacheService.RemoveAsync(cacheKey);
        //        return Ok("Vui lòng kiểm tra email của bạn để đặt lại mật khẩu.");
        //    }
        //    await cacheService.SetAsync(cacheKey, userId, TimeSpan.FromHours(1));
        //    string resetPasswordLink = "https://localhost:7174/api/users/reset-password/" + resetToken;
        //    await _mailService.SendResetPasswordEmail(user.Email, resetPasswordLink);
        //    return Ok("Vui lòng kiểm tra email của bạn để đặt lại mật khẩu.");
        //}
        #endregion
        #region Reset password
        [HttpPut("reset-password/{resetToken}")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(string resetToken, [FromBody] UserResetPasswordRequest request, [FromServices] IMemoryCache cacheService)
        {
            var validationResult = await _userResetPasswordRequest.ValidateAsync(request);
            if (!validationResult.IsValid)
            {
                // Xử lý khi validation không thành công
                return BadRequest(validationResult.Errors);
            }
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

            string passwordHash = Helper.HashValue.ComputeHmacSHA512(request.NewPassword, user.PasswordSalt);
            user.PasswordHash = passwordHash;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            cacheService.Remove(cacheKey);

            return Ok("Đổi mật khẩu thành công.");
        }
        #endregion
        #region Get my profile
        [HttpGet("me")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userIdString = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(userIdString, out Guid userId))
            {
                return BadRequest("Không tìm thấy thông tin người dùng hoặc giá trị không hợp lệ.");
            }

            var user = await _context.Users
                         .Where(u => u.UserId == userId)
                           .Select(u => new GetUserRequest()
                           {
                               UserName = u.UserName,
                               FullName = u.FullName,
                               AvatarUrl = u.AvatarUrl,
                               Email = u.Email,
                               EmailConfirmed = u.EmailConfirmed,
                           }).FirstOrDefaultAsync();
            if (user == null)
            {
                return NotFound("Không tìm thấy thông tin người dùng.");
            }
            return Ok(user);
        }
        #endregion
        #region Update my profile
        [HttpPut("me")]
        public async Task<IActionResult> UpdateCurrentUser([FromBody] UpdateMyProfileRequest userUpdate)
        {
            var validationResult = await _updateMyProfileRequest.ValidateAsync(userUpdate);
            if (!validationResult.IsValid)
            {
                // Xử lý khi validation không thành công
                return BadRequest(validationResult.Errors);
            }
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
            user.FullName = CultureInfo.CurrentCulture.TextInfo.ToTitleCase(userUpdate.FullName.ToLower());
            user.Email = userUpdate.Email;
            user.AvatarUrl = userUpdate.AvatarUrl;
            _context.SaveChanges();
            return Ok("Thông tin người dùng đã được cập nhật thành công.");
        }
        #endregion
        #region Get user listing
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<GetUserRequest>), StatusCodes.Status200OK)]
        public async Task<IActionResult> GetAllAsnyc([FromQuery] UserFilterRequest userFilterRequest)
        {
            var users = await _context.Users
                            .Where(u =>
                                (string.IsNullOrEmpty(userFilterRequest.Keyword) || (!string.IsNullOrEmpty(userFilterRequest.Keyword) && (u.UserName.Contains(userFilterRequest.Keyword) || u.Email.Contains(userFilterRequest.Keyword)))) &&
                                (!userFilterRequest.Type.HasValue || (userFilterRequest.Type.HasValue && u.Type == userFilterRequest.Type.Value)) &&
                                (!userFilterRequest.Status.HasValue || (userFilterRequest.Status.HasValue && u.Status == userFilterRequest.Status.Value))
                            ).Select(u => new GetUserRequest()
                            {
                                UserId = u.UserId,
                                UserName = u.UserName,
                                FullName = u.FullName,
                                AvatarUrl = u.AvatarUrl,
                                Email = u.Email,
                                Type = u.Type,
                                Status = u.Status,
                                EmailConfirmed = u.EmailConfirmed,
                            }).ToListAsync();
            return Ok(users);
        }

        #endregion
        #region Create new user
        [HttpPost("create")]
        public async Task<IActionResult> CreateUser([FromBody] UserCreateRequest userCreate)
        {

            var validationResult = await _userCreateRequest.ValidateAsync(userCreate);
            if (!validationResult.IsValid)
            {
                // Xử lý khi validation không thành công
                return BadRequest(validationResult.Errors);
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
            string passwordSalt = HashValue.GenerateKey();
            string passwordHash = HashValue.ComputeHmacSHA512(userCreate.Password, passwordSalt);
            var userId = Guid.NewGuid();
            var newUser = new Users
            {
                UserId = userId,
                UserName = userCreate.UserName,
                FullName = CultureInfo.CurrentCulture.TextInfo.ToTitleCase(userCreate.FullName.ToLower()),
                Email = userCreate.Email,
                AvatarUrl = userCreate.AvatarUrl,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                ModifierId = userId,
                LastSignInTime = DateTime.Now,
                ModfiedTime = DateTime.Now,
                Type = UserType.User,
                EmailConfirmed = true,
            };
            _context.Users.Add(newUser);
            var userSubscription = new UserSubscriptions
            {
                UserSubscription = Guid.NewGuid(),
                UserId = userId,
                Type = UserSubScriptionType.Free,
                Price = 0,
                MaximumTodo = 10,
                Status = UserSubScriptionStatus.Cancelled,
                StartTime = DateTime.Now,
                CreateTime = DateTime.Now,
                CreatorId = userId,
                ModifierId = userId,
            };
            _context.UserSubscriptions.Add(userSubscription);
            _context.SaveChanges();
            return Ok("Người dùng đã được tạo thành công.");
        }
        #endregion
        #region Update exist user
        [HttpPut("update/{userId:guid}")]
        public async Task<IActionResult> UpdateUser(Guid userId, [FromBody] UserUpdateRequest userUpdate)
        {
            var validationResult = await _userUpdateRequest.ValidateAsync(userUpdate);
            if (!validationResult.IsValid)
            {
                // Xử lý khi validation không thành công
                return BadRequest(validationResult.Errors);
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
            user.Type = userUpdate.Type;

            await _context.SaveChangesAsync();

            return Ok("Người dùng đã được cập nhật thành công.");
        }
        #endregion
        private string GenerateToken(Guid userId)
        {
            TokenSettingsRequest tokenSettings = _configuration.GetSection("TokenSettings").Get<TokenSettingsRequest>();
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
            TokenSettingsRequest tokenSettings = _configuration.GetSection("TokenSettings").Get<TokenSettingsRequest>();
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
                    jwtSecurityToken.ValidTo >= DateTime.Now &&
                    jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value == userId.ToString())
                {
                    return true;
                }
            }
            catch (Exception)
            {
            }
            return false;
        }
    }
}
