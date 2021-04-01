using System;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Web;

namespace keyvault.obo.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class SecretController : ControllerBase
    {


        private readonly ILogger<SecretController> _logger;
        private readonly IConfiguration _config;
        private readonly ITokenAcquisition _tokenAcquisition;

        public SecretController(ILogger<SecretController> logger, ITokenAcquisition tokenAcquisition, IConfiguration appConfig)
        {
            this._tokenAcquisition = tokenAcquisition;
            this._logger = logger;
            this._config = appConfig;
        }

        [HttpGet]
        public async Task<IActionResult> GetAsync()
        {
            return Ok(await KeyVaultClient.ListSecrets((new OnBehalfOfCredential(_config["AzureAd:ClientId"],_config["AzureAd:ClientSecret"], await GetToken())), _config["AppConfiguration:KeyvaultUrl"]));
        }

        [HttpGet("{SecretId}")]
        public async Task<IActionResult> GetAsync(string SecretId)
        {
            var s = KeyVaultClient.GetSecret((new OnBehalfOfCredential(_config["AzureAd:ClientId"],_config["AzureAd:ClientSecret"], await GetToken())), _config["AppConfiguration:KeyvaultUrl"], SecretId);
            
            return Ok(s);
        }

        [HttpPost("{SecretId}/update")]
        public async Task<IActionResult> GetAsync(string SecretId, [FromBody]string secret)
        {
            return Ok(KeyVaultClient.UpdateSecret((new OnBehalfOfCredential(_config["AzureAd:ClientId"],_config["AzureAd:ClientSecret"], await GetToken())), _config["AppConfiguration:KeyvaultUrl"], SecretId, secret));
        }

        [HttpPost]
        public async Task<IActionResult> PostAsync(KeyVaultSecret secret)
        {
            return Ok(KeyVaultClient.CreateSecret((new OnBehalfOfCredential(_config["AzureAd:ClientId"],_config["AzureAd:ClientSecret"], await GetToken())), _config["AppConfiguration:KeyvaultUrl"], secret));
        }

        private async Task<string> GetToken()
        {
            return await _tokenAcquisition.GetAccessTokenForUserAsync(new[] { String.Format("api://{0}/{1}",_config["AzureAd:ClientId"],_config["AppConfiguration:ApiScope"]) });
        }
    }
}

