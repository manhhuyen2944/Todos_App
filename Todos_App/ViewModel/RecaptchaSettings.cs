namespace Todos_App.ViewModel
{
    public class RecaptchaSettings
    {
        public string SiteKey { get; set; }
        public string SecretKey { get; set; }
        public bool Enable { get; set; }
        public bool Status { get; set; }
        public double Score { get; set; }
        public string  Endpoint { get; set; }
    }
}
