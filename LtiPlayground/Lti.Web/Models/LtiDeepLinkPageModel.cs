using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lti.Web.Models
{
    public class LtiDeepLinkPageModel
    {
        public string TokenContents { get; set; }
        public string ReturnUrl { get; set; }

        public string IDToken { get; set; }
        //public string Data { get; set; }
    }
}
