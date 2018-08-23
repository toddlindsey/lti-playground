using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lti.Web.Services
{
    public static class LtiClaims
    {
        public const string Base = "https://purl.imsglobal.org/spec/lti/claim/";
        public const string DeepLinkBase = "https://purl.imsglobal.org/spec/lti-dl/claim/";

        // Common
        public const string MessageType = Base + "message_type";
        public const string Version = Base + "version";
        public const string DeploymentId = Base + "deployment_id";

        // Deep Linking
        public const string DeepLinkingSettings = DeepLinkBase + "deep_linking_settings";
        public const string ContentItems = DeepLinkBase + "content_items";
        public const string Data = DeepLinkBase + "data";
    }
}
