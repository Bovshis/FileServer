using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Shapes;
using Client.Models;
using Newtonsoft.Json;
using JsonSerializer = Newtonsoft.Json.JsonSerializer;

namespace Client.Services
{
    internal class UserService : IUserService, IDisposable
    {
        private readonly IAesSecurityService _aesSecurityService;
        private readonly HttpClient _httpClient;

        public Guid ClientId { get; set; }

        public UserService(HttpClient httpClient, IAesSecurityService aesSecurityService)
        {
            _aesSecurityService = aesSecurityService;
            _httpClient = httpClient;
        }

        public async Task<string> LogInAsync(string userEmail, string userPassword)
        {
            var loginRequest = new LoginRequest() { Email = userEmail, Password = userPassword };
            var regResponse = await _httpClient.PostAsJsonAsync("/api/Security/login", loginRequest);
            if (!regResponse.IsSuccessStatusCode)
            {
                return $"Login failed! Status code: {await regResponse.Content.ReadAsStringAsync()}";
            }

            var token = await regResponse.Content.ReadAsStringAsync();
            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
            return $"Login successfully! JwtToken: {token}";
        }

        public async Task<string> CreateConnectionAsync()
        {
            if (_httpClient.DefaultRequestHeaders.Authorization is null)
            {
                return "Please Login first";
            }

            ClientId = Guid.NewGuid();
            using var ecdh = new ECDiffieHellmanCng();
            ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ecdh.HashAlgorithm = CngAlgorithm.Sha256;
            var clientPublicKey = ecdh.PublicKey.ToByteArray();

            var response = await _httpClient.PostAsJsonAsync("/api/Security/generate-session-key", new { ClientId, ClientPublicKey = clientPublicKey });
            if (!response.IsSuccessStatusCode)
            {
                return $"Connection failed! Status code: {await response.Content.ReadAsStringAsync()}";
            }

            var generateSessionKeyResponse = await response.Content.ReadAsAsync<GenerateSessionKeyResponse>();
            var sessionKey = ecdh.DeriveKeyMaterial(CngKey.Import(generateSessionKeyResponse.PublicEcdfKey, CngKeyBlobFormat.EccPublicBlob));
            _aesSecurityService.SetAesConfiguration(sessionKey, generateSessionKeyResponse.IV);
            return $"Connection established! Secret Key: {Encoding.UTF8.GetString(sessionKey)}";
        }

        public void Dispose()
        {
            _httpClient.Dispose();
        }
    }
}