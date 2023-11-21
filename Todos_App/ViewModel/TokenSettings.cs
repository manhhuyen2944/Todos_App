namespace Todos_App.ViewModel
{
    public class TokenSettings
    {
        public string SecretKey { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public int ExpirationHours { get; set; }
    }
}
