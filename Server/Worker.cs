using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Server
{
#region Worker
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly IHubContext<TestHub> _clockHub;

        public Worker(ILogger<Worker> logger, IHubContext<TestHub> clockHub)
        {
            _logger = logger;
            _clockHub = clockHub;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation($"Enter");
            while (!stoppingToken.IsCancellationRequested)
            {

                if(TestHub.queueHub.TryTake(out string msg))
                {
                    _logger.LogInformation($"Msg {msg}");

                    //foreach (var c in TestHub.listOfString)
                    //{ _logger.LogInformation($"Msg {c}");
                    //}
                }
                //_logger.LogInformation("Worker running at: {Time}", DateTime.Now);
                //await _clockHub.Clients.All.SendAsync(DateTime.Now);
                
                await Task.Delay(30);
            }

            _logger.LogInformation($"leave");
        }
    }
#endregion
}