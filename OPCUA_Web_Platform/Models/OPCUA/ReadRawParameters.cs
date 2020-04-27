using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebPlatform.Models.OPCUA
{
    public class ReadRawParameters
    {
        public bool bIsReadModified { get; set; }
        public string  dateStartDateTime { get; set; }
        public  string  dateEndDateTime { get; set; }
        public int iMaxReturnVal { get; set; }
        public List<string> lstNodeId { get; set; }
        ReadRawParameters()
        {
            lstNodeId = new List<string>();
        }
        public bool IsValid()
        {
            return
                   lstNodeId.Count > 0 &&
                   iMaxReturnVal > 0;
                  
        }


    }
}
