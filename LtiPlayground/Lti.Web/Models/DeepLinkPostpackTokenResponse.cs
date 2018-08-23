using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lti.Web.Models
{
    [JsonObject]
    public class DeepLinkPostpackTokenResponse
    {
        public string IDToken { get; set; }
    }
}
