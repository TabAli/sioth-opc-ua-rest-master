using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebPlatform.Models.DataSet;

namespace WebPlatform.Models.OPCUA
{
    public class WriteParameters
    {
        public List<string> listOfNodeId { get; set; }
        public List<VariableState> listOfVaribleState { get; set; }
        WriteParameters()
        {
            listOfNodeId = new List<string>();
            listOfVaribleState = new List<VariableState>();
        }


    }
}
