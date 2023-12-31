using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Reflection;
using System.Text;
using Todos_App.Data;
using Todos_App.Services;
using Todos_App.Validation;
using Todos_App.ViewModel;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
//FluentValidation
//builder.Services.AddScoped<IValidator<UserSignInRequest>, UserSignInRequestValidator>();
//builder.Services.AddScoped<IValidator<GetUserRequest>, GetUserRequestValidator>();
//builder.Services.AddScoped<IValidator<UpdateMyProfileRequest>, UpdateMyProfileRequestValidator>();
//builder.Services.AddFluentValidationAutoValidation();
//builder.Services.AddFluentValidationClientsideAdapters();
//builder.Services.AddValidatorsFromAssembly(typeof(UserSignInRequestValidator).Assembly);
builder.Services.AddValidatorsFromAssembly(Assembly.GetExecutingAssembly());
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddFluentValidationClientsideAdapters();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<ToDosContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("ToDo_Apps")));
// Send Email
builder.Services.Configure<MailSettingsRequest>(builder.Configuration.GetSection("MailSettings"));
builder.Services.AddScoped<IMailService, MailService>();
// Recaptcha
builder.Services.Configure<RecaptchaSettingsRequest>(builder.Configuration.GetSection("RecaptchaSettings"));
builder.Services.Configure<MailSettingsRequest>(builder.Configuration.GetSection("AppSettings"));
builder.Services.AddScoped<IRecaptchaService, RecaptchaService>();
builder.Services.AddHttpClient();
builder.Services.AddMemoryCache();
builder.Services.AddStackExchangeRedisCache(redisOptions =>
{
    string redisConnectionString = builder.Configuration.GetConnectionString("Redis");
    redisOptions.Configuration = redisConnectionString;
});
//JWT
builder.Services.Configure<TokenSettingsRequest>(builder.Configuration.GetSection("TokenSettings"));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var tokenSettings = builder.Configuration.GetSection("TokenSettings").Get<TokenSettingsRequest>();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = tokenSettings.Issuer,
            ValidAudience = tokenSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenSettings.SecretKey)),
        };
    });


builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
