using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Client.Models;
using Aes = System.Runtime.Intrinsics.Arm.Aes;

namespace Client.Services
{
    internal class TextService : ITextService, IDisposable
    {
        private readonly IUserService _userService;
        private readonly IAesSecurityService _aesSecurityService;
        private readonly HttpClient _httpClient;

        public TextService(IUserService userService, HttpClient httpClient, IAesSecurityService aesSecurityService)
        {
            _userService = userService;
            _aesSecurityService = aesSecurityService;
            _httpClient = httpClient;
        }

        public string EncryptedText { get; set; } = string.Empty;

        public string DecryptedText { get; set; } = string.Empty;

        public async Task<string> GetTextAsync(string textName)
        {
            var encryptedFileName = await _aesSecurityService.EncryptTextAsync(textName);
            var base64EncryptedFileName = Convert.ToBase64String(encryptedFileName, 0, encryptedFileName.Length);
            base64EncryptedFileName = HttpUtility.UrlEncode(base64EncryptedFileName);

            var response = await _httpClient.GetAsync($"api/Text/get-text?base64EncryptedTextName={base64EncryptedFileName}&clientId={_userService.ClientId}");
            if (!response.IsSuccessStatusCode)
            {
                return $"Text didn't delete! Status code: {response.StatusCode} {await response.Content.ReadAsStringAsync()}";
            }

            EncryptedText = await response.Content.ReadAsStringAsync();
            var contentStream = await response.Content.ReadAsStreamAsync();
            DecryptedText = await _aesSecurityService.DecryptTextAsync(contentStream);

            return "Text got successfully!";
        }

        public async Task<string> DeleteTextAsync(string textName)
        {
            var encryptedFileName = await _aesSecurityService.EncryptTextAsync(textName);
            var base64EncryptedFileName = Convert.ToBase64String(encryptedFileName, 0, encryptedFileName.Length);
            base64EncryptedFileName = HttpUtility.UrlEncode(base64EncryptedFileName);

            var response = await _httpClient.DeleteAsync($"api/Text/delete-text?base64EncryptedTextName={base64EncryptedFileName}&clientId={_userService.ClientId}");
            if (!response.IsSuccessStatusCode)
            {
                return $"Text didn't delete! Status code: {response.StatusCode} {await response.Content.ReadAsStringAsync()}";
            }

            return "Text deleted!";
        }

        public async Task<string> EditTextAsync(string textName, string editedText)
        {
            var encryptedFileName = await _aesSecurityService.EncryptTextAsync(textName);
            var base64EncryptedFileName = Convert.ToBase64String(encryptedFileName, 0, encryptedFileName.Length);
            base64EncryptedFileName = HttpUtility.UrlEncode(base64EncryptedFileName);

            var encryptedText = await _aesSecurityService.EncryptTextAsync(DecryptedText);
            var content = new ByteArrayContent(encryptedText);
            var response = await _httpClient.PutAsync($"api/Text/edit-text?base64EncryptedTextName={base64EncryptedFileName}&clientId={_userService.ClientId}", content);
            if (!response.IsSuccessStatusCode)
            {
                return $"Text didn't edit/create! Status code: {response.StatusCode} {await response.Content.ReadAsStringAsync()}";
            }

            return "Text edited";
        }

        public void Dispose()
        {
            _httpClient.Dispose();
        }
    }
}
