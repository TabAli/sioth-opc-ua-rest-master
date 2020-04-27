using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebPlatform.Models.OPCUA
{
    public class OPCUATag
    {
        public string index { get; set; } 
        public string data { get; set; }
        public string value { get; set; }
        public string quality { get; set; }
        public OPCUATag()
        {


        }

        public OPCUATag(string Index,string Data,string Value,string Quality)
        {
            this.index = Index;
            this.data = Data;
            this.value = Value;
            this.quality = Quality;
        }


    }
}
