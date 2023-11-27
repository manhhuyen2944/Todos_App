namespace Todos_App.ViewModel
{
    public class OkResponseModel : BaseResponseModel
    {
        public OkResponseModel()
        {
        }

        public OkResponseModel(string message)
        {
            Message = message;
        }
    }

    public class OkResponseModel<T> : BaseResponseModel where T : class, new()
    {
        public T Data { get; set; }

        public OkResponseModel()
        {
            Data = default;
        }

        public OkResponseModel(T data, string errorMessage = null)
        {
            Data = data;
            ErrorMessage = errorMessage;
        }

        public OkResponseModel(T data, string message, string errorMessage = null)
        {
            Data = data;
            Message = message;
            ErrorMessage = errorMessage;
        }
    }
}
