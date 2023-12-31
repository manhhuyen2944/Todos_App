﻿using Newtonsoft.Json;
using System.Net;
using Todos_App.Caching;
using Todos_App.ViewModel;

namespace Todos_App.Services
{
    public class RecaptchaService : IRecaptchaService
    {
        private readonly RecaptchaSettingsRequest _recaptchaSettings;
        public RecaptchaService(IConfiguration configuration)
        {
            _recaptchaSettings = configuration.GetOptions<RecaptchaSettingsRequest>();
        }

        public async Task<bool> VerifyRecaptchaAsync(string recaptchaToken, CancellationToken cancellationToken)
        {
            if (!_recaptchaSettings.Enable)
            {
                return true;
            }

            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri(_recaptchaSettings.Endpoint);
                var payload = new FormUrlEncodedContent(new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("secret", _recaptchaSettings.SecretKey),
                    new KeyValuePair<string, string>("response", recaptchaToken)
                });

                var httpResponse = await httpClient.PostAsync(string.Empty, payload, cancellationToken).ConfigureAwait(false);

                if (httpResponse.StatusCode == HttpStatusCode.OK)
                {
                    var data = JsonConvert.DeserializeObject<RecaptchaSettingsRequest>(await httpResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
                    return data != null && data.Status && data.Score >= 0.5f;
                }
            }

            return false;
        }
    }
}
