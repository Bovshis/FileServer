using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Client.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;

namespace Client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly IUserService _userService;
        private readonly ITextService _textService;

        public MainWindow()
        {
            var serviceProvider = new ServiceCollection()
                .AddHttpClient("WpfClient", client => client.BaseAddress = new Uri("https://localhost:7053"))
                .Services.BuildServiceProvider();
            var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            //var aesSecurityService = serviceProvider.GetService<IAesSecurityService>();


            IAesSecurityService aesSecurityService = new AesSecurityService();
            var httpClient = new HttpClient()
            {
                BaseAddress = new Uri("https://10.160.88.211:7053"),
                //BaseAddress = new Uri("https://localhost:7053")
            };
            _userService = new UserService(httpClient, aesSecurityService);
            _textService = new TextService(_userService, httpClient, aesSecurityService);
            InitializeComponent();
        }

        private async void GetText_OnClick(object sender, RoutedEventArgs e)
        {
            var responseMessage = await _textService.GetTextAsync(TextName.Text);
            EncryptedText.Text = _textService.EncryptedText;
            DecryptedText.Text = _textService.DecryptedText;
            MessageBox.Show(responseMessage);
        }

        private async void EditText_OnClick(object sender, RoutedEventArgs e)
        {
            _textService.DecryptedText = DecryptedText.Text;
            var responseMessage = await _textService.EditTextAsync(TextName.Text, DecryptedText.Text);
            MessageBox.Show(responseMessage);
        }

        private async void DeleteText_OnClick(object sender, RoutedEventArgs e)
        {
            var responseMessage = await _textService.DeleteTextAsync(TextName.Text);
            MessageBox.Show(responseMessage);
        }

        private async void LogIn_OnClick(object sender, RoutedEventArgs e)
        {
            var message = await _userService.LogInAsync(UserName.Text, UserPassword.Password);
            MessageBox.Show(message);
        }

        private async void CreateConnection_OnClick(object sender, RoutedEventArgs e)
        {
            var message = await _userService.CreateConnectionAsync();
            MessageBox.Show(message);
        }
    }
}
