namespace Todos_App.ViewModel
{
    public class BaseResponseModel
    {
        public string ErrorMessage { get; set; }
        public string Token { get; set; }

        public string Message { get; set; }

        public bool Status => string.IsNullOrEmpty(ErrorMessage);

        public BaseResponseModel()
        {
        }

        public BaseResponseModel(string message)
        {
            Message = message;
        }
        public BaseResponseModel(string message, string token)
        {
            Message = message;
            Token = token;
        }
    }
}
