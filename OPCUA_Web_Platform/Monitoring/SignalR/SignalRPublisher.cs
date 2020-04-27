
using Microsoft.AspNetCore.SignalR.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebPlatform.Monitoring.SignalR
{
    interface ISignalRPublisher : IPublisher { }
    public class SignalRPublisher: ISignalRPublisher
    {
        //private readonly IHubProxy _hub;
        HubConnection connection;
        // private static readonly Dictionary<string, IHubProxy> ClientsDict = new Dictionary<string, IHubProxy>();
        private static readonly Dictionary<string, HubConnection> ClientsDict = new Dictionary<string, HubConnection>();
        public SignalRPublisher(string signalRUrl)
        {
            lock (ClientsDict)
            {
                if (ClientsDict.ContainsKey(signalRUrl))
                {
                   // _hub = ClientsDict[signalRUrl];
                }
                else
                    try
                {      
                    {
                             connection = new HubConnectionBuilder()
                         .WithUrl(signalRUrl)
                              .Build();

                            //var hubConnection = new HubConnection(signalRUrl);
                            //    hubConnection.StateChanged += HubConnection_StateChanged;
                            //    _hub = hubConnection.CreateHubProxy("TestHub");
                            //    _hub.On<string, string>("SendAsync", (name, message) => returnTrue());

                            //hubConnection.Start().Wait();
                            connection.StartAsync().Wait();

                            ClientsDict.Add(signalRUrl, connection);
                    }
                }catch(Exception e)
                {
                    string mesg = e.Message;
                }
            }
        }

        public void Publish(string topic, string message)
        {
            // _hub.Invoke("Send", message, topic);
            connection.InvokeAsync("Send", message, topic);
        }
       

       
    }
}
