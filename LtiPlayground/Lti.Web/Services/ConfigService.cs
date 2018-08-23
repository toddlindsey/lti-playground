using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lti.Web.Services
{
    public class ConfigService
    {
        private readonly IConfiguration config;

        public ConfigService(IConfiguration config)
        {
            this.config = config;
        }

        public string PlatformId => this.config.GetValue<string>("auth:openid:platformid");
        public string ClientId => this.config.GetValue<string>("auth:openid:clientid");
        public string Audience => this.config.GetValue<string>("auth:openid:audience");
        public string Authority => this.config.GetValue<string>("auth:openid:authority");
        public string PlatformKey => this.config.GetValue<string>("auth:openid:platformkey");
        public string ToolPrivateKey => this.config.GetValue<string>("auth:openid:toolprivatekey");
        public string PlatformTokenEndpoint => this.config.GetValue<string>("auth:openid:platformtokenendpoint");
    }
}
