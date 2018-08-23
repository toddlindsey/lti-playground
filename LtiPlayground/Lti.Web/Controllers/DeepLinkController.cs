using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Lti.Web.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Extensions.Configuration;
using System.Text;
using System.Threading;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Lti.Web.Services;
using Newtonsoft.Json;

namespace Lti.Web.Controllers
{
    // [Authorize]
    [Route("api/deepLink")]
    public class DeepLinkController : Controller
    {
        private readonly ConfigService config;

        public DeepLinkController(ConfigService config)
        {
            this.config = config;
        }

        [HttpPost]
        public async Task<IActionResult> DeepLink([FromForm] LtiDeepLinkRequest linkRequest)
        {
            JwtSecurityToken token = await ReadAndValidateDeepLinkRequestToken(linkRequest.id_token);

            string returnUrl;
            JwtSecurityToken postbackToken = this.BuildDeepLinkPostbackToken(token, out returnUrl);

            var handler = new JwtSecurityTokenHandler();
            string serializedToken = handler.WriteToken(postbackToken);

            string encodedPayload = serializedToken.Split('.')[1];
            string decodedPayload = Base64UrlDecode(encodedPayload);
            object jsonObject = JsonConvert.DeserializeObject(decodedPayload);
            string formattedPayload = JsonConvert.SerializeObject(jsonObject, Formatting.Indented);

            var model = new LtiDeepLinkPageModel
            {
                TokenContents = formattedPayload,
                ReturnUrl = returnUrl,
                IDToken = serializedToken
            };
            return View("DeepLinks", model);
        }

        [HttpGet]
        [Route("keys")]
        public IActionResult Keys()
        {
            // logic to lookup platform's jwks_uri by clientId - since that info should be stored on our end after platform / tool integration
            // for test purposes - hardcode to our RI test integration point
            string platformJwks = $"https://lti-ri.imsglobal.org/platforms/{this.config.PlatformId}/platform_keys.json";

            return Ok(new
            {
                jwks_uri = platformJwks
            });
        }

        [HttpPost]
        [Route("generate-postback")]
        public IActionResult GeneratePostbackToken([FromBody]DeepLinkPostbackTokenRequest tokenRequest)
        {
            return Ok();
        }

        // A helper method for properly base64url decoding the payload
        public static string Base64UrlDecode(string value, Encoding encoding = null)
        {
            string urlDecodedValue = value.Replace('_', '/').Replace('-', '+');

            switch (value.Length % 4)
            {
                case 2:
                    urlDecodedValue += "==";
                    break;
                case 3:
                    urlDecodedValue += "=";
                    break;
            }

            return Encoding.ASCII.GetString(Convert.FromBase64String(urlDecodedValue));
        }

        private JwtSecurityToken BuildDeepLinkPostbackToken(JwtSecurityToken requestToken, out string returnUrl)
        { 
            Claim linkSettings = requestToken.Claims.Single(x => x.Type == LtiClaims.DeepLinkingSettings);

            JObject settingValues = JObject.Parse(linkSettings.Value);

            returnUrl = (string)settingValues["deep_link_return_url"];
            string data = (string)settingValues["data"];

            // first - read tool's private key
            RSAParameters rsaParams;
            using (var tr = new StringReader(this.config.ToolPrivateKey))
            {
                var pemReader = new PemReader(tr);
                var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                if (keyPair == null)
                {
                    throw new Exception("Could not read RSA private key");
                }
                var privateRsaParams = keyPair.Private as RsaPrivateCrtKeyParameters;
                rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);
            }

            // create security key using private key above
            var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaParams);

            // note that securityKey length should be >256b so you have to make sure that your private key has a proper length
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256);

            //  create a Token
            var clientAsssertionJwtTokenHeader = new JwtHeader(signingCredentials);

            // Some PayLoad that contain information about the caller (tool)
            // expected payload for access token request.. confirm with IMS guys
            var now = DateTime.UtcNow;
            var clientAsssertionJwtTokenPayload = new JwtPayload
                {
                    { "iss", this.config.ClientId },
                    //{ "aud", this.config.PlatformTokenEndpoint },
                    { "aud", requestToken.Issuer },
                    { "exp", now.AddMinutes(5).Ticks }, // give the user 5 minutes to post the deep link?
                    { "iat", now.Ticks },
                    { "jti", $"{this.config.ClientId}-{now.Ticks}" },
                    { "nonce", "377fdbf8cbc2f7b0799b" }
                };

            Claim[] deepLinkResponseClaims = this.BuildResponseClaims(data);
            clientAsssertionJwtTokenPayload.AddClaims(deepLinkResponseClaims);

            var clientAsssertionJwtToken = new JwtSecurityToken(clientAsssertionJwtTokenHeader, clientAsssertionJwtTokenPayload);
            return clientAsssertionJwtToken;

        }

        private Claim[] BuildResponseClaims(string platformData)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(LtiClaims.MessageType, "LtiDeepLinkingResponse"));
            claims.Add(new Claim(LtiClaims.Version, "1.3.0"));
            claims.Add(new Claim(LtiClaims.DeploymentId, this.config.PlatformId));

            var contentItems = new object[] {
                new {
                    type = "ltiLink",
                    title = "My Course Title",
                    url = "http://my.course.url",
                    lineItem = new
                    {
                        scoreMaximum = 100,
                        label = "Line Item Label",
                        resourceId = "lineItemResourceId",
                        tag = "lineItemTag"
                    }
                }
            };

            var linkClaim = new Claim(LtiClaims.ContentItems, JArray.FromObject(contentItems).ToString(), JsonClaimValueTypes.JsonArray);
            claims.Add(linkClaim);
            claims.Add(new Claim(LtiClaims.Data, platformData));

            return claims.ToArray();
        }

        private async Task<JwtSecurityToken> ReadAndValidateDeepLinkRequestToken(string encodedJwtToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            if (!tokenHandler.CanReadToken(encodedJwtToken))
                throw new SecurityTokenValidationException($"String is not a well formed JWT: {encodedJwtToken}");

            var jwtToken = (JwtSecurityToken) tokenHandler.ReadToken(encodedJwtToken);

            if (!tokenHandler.CanValidateToken)
                throw new SecurityTokenValidationException($"Cannot validate JWT");

            Claim messageTypeClaim = jwtToken.Claims.FirstOrDefault(x => x.Type == LtiClaims.MessageType);
            if( messageTypeClaim == null )
                throw new SecurityTokenValidationException($"No message_type claim provided");

            if (messageTypeClaim.Value != "LtiDeepLinkingRequest")
                throw new SecurityTokenValidationException("messag_type claim is not LtiDeepLinkingRequest");

            // test token validation - change kid, issuer, etc to something else in debugger, make sure validation fails
            // unit test this logic
            // try to tamper with other incoming token params 
            //jwtToken.Header.Kid = "123";
            //jwtToken.Issuer = "123";
            // since validation accepts encoded token string only, write modified token back to string
            //encodedJwtToken = tokenHandler.WriteToken(jwtToken);

                // now we specify what to validate - go thru all exceptions there (lifetime, etc)
                // openIdConfig.SigningKeys will get those keys openid connect infrastructure got from platform_keys - confirm 
                // see if there is an easier way to do this without faking openid_config
                // also try changing key or something and see how validation fails 

            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(this.config.PlatformKey));

            IConfigurationManager<OpenIdConnectConfiguration> configurationManager =
                new ConfigurationManager<OpenIdConnectConfiguration>($"https://localhost:44307/api/deepLink/keys", new OpenIdConnectConfigurationRetriever());

            OpenIdConnectConfiguration openIdConfig = await configurationManager.GetConfigurationAsync(CancellationToken.None);

            Microsoft.IdentityModel.Tokens.TokenValidationParameters validationParameters =
                new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidIssuer = this.config.ClientId,
                    ValidAudience = this.config.Audience,
                    IssuerSigningKeys = openIdConfig.SigningKeys,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidateActor = true,
                    RequireExpirationTime = true,
                    ValidateLifetime = true,
                    RequireSignedTokens = true,
                    SaveSigninToken = false
                };

            Microsoft.IdentityModel.Tokens.SecurityToken validatedSecurityToken;
            ClaimsPrincipal validClaimsPrincipal = tokenHandler.ValidateToken(encodedJwtToken, validationParameters, out validatedSecurityToken);

            if (validatedSecurityToken == null)
                throw new SecurityTokenValidationException($"Validation failed for JWT: {encodedJwtToken}");

            return jwtToken;
        }
    }
}
