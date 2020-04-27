using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebPlatform.Models.OPCUA
{
    public class OPCUAServer
    {
        public string serverName { get; set; }
        public string protocol { get; set; }
        public string messageEncoding { get; set; }
        public string securityMode { get; set; }
        public string securityPolicy {get;set;}
        public string UserIdentity { get; set; }
        public string UserIdentityString { get; set; }
        public string certificationPath { get; set; }
        public string certificationPassword { get; set; }
        public string certificationStore { get; set; }
        public string userName { get; set; }
        public string userPassword { get; set; }
        public bool IsSecurityStoreEnabled { get; set; }

    }
}
