using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lti.Web.Models
{
    public class LtiDeepLinkRequest
    {
        public string utf8 { get; set; }
        public string authenticity_token { get; set; }
        public string id_token { get; set; }
        public string commit { get; set; }
    }
}
