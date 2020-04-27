using System;


using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;

namespace Server
{

    public class TestHub : Hub
    {
        public static List<string>  listOfString = new List<string>();
        public static BlockingCollection<string> queueHub = new BlockingCollection<string>(7000);

        public async Task Send(string msg,string topic)
        {
            await Clients.All.SendAsync(msg);
            listOfString.Add(msg);
            queueHub.TryAdd(msg);
            //dicArchiverData[newData.archiver.ArchiverName].TryAdd(copyListItems);
        }
    }

}