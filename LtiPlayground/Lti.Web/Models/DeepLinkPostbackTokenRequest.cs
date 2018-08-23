using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lti.Web.Models
{
    [JsonObject]
    public class DeepLinkPostbackTokenRequest
    {
        public string ReturnUrl { get; set; }
        public string Data { get; set; }
        public IReadOnlyList<string> CourseIDs { get; set; }
    }
}
