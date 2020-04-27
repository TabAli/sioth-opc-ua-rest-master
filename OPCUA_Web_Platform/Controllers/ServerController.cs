using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using WebPlatform.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Schema;
using NJsonSchema;
using Opc.Ua;
using Opc.Ua.Client;
using WebPlatform.Models.DataSet;
using WebPlatform.Models.OptionsModels;
using WebPlatform.Models.OPCUA;
using WebPlatform.OPCUALayer;
using WebPlatform.Exceptions;
using Microsoft.AspNetCore.SignalR.Client;


// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebPlatform.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ServerController : Controller
    {
        private readonly OPCUAServers[] _uaServers;
        private readonly IUaClientSingleton _uaClient;

        public ServerController(IOptions<OPCUAServersOptions> servers, IUaClientSingleton UAClient)
        {
            this._uaServers = servers.Value.Servers;
            for (int i = 0; i < _uaServers.Length; i++) _uaServers[i].Id = i;

            this._uaClient = UAClient;
        }

        #region Session Management

        [HttpPost("Sessions/{sessionName}/open")]
        public async Task<IActionResult>OpenSession(string sessionName,OPCUAServer uaSever )
        {
            try
            {
              bool bSession= await _uaClient.CheckSession(sessionName);
                if(bSession)
                {
                    return BadRequest(new
                    {
                        error =$"A session with the same name {sessionName} is already created"
                    });
                }
                else
                {
                    var session =await _uaClient.CreateSession(uaSever, sessionName);
                    if(session==null)
                    {
                        return BadRequest(new
                        {
                            error = $"Failed to create session {sessionName}"
                        });
                    }
                    else
                    {
                        return Ok($"Session {sessionName} is created successfully");
                    }
                }
            }
            catch(Exception e)
            {
                return BadRequest(new
                {
                    error = $"Failed to create session {sessionName}:{e.Message}"
                });
            }
        }

        #endregion

        #region Browse Server
        [HttpGet("sessions/{sessionName}/nodes/{node_id:regex(^\\d+-(?:(\\d+)|(.+))$)?}")]
        public async Task<IActionResult> GetNode(string sessionName, string node_id = "0-85")
        {


            if (!await _uaClient.CheckSession(sessionName))
                return StatusCode(500, $"The session {sessionName} NotAvailable");

            var decodedNodeId = WebUtility.UrlDecode(node_id);

            var result = new JObject();

            try
            {
                var sourceNode = await _uaClient.ReadNodeAsync(sessionName, decodedNodeId);
                result["node-id"] = decodedNodeId;
                result["name"] = sourceNode.DisplayName.Text;

                switch (sourceNode.NodeClass)
                {
                    case NodeClass.Method:
                        result["type"] = "method";
                        break;
                    case NodeClass.Variable:
                        result["type"] = "variable";
                        var varNode = (VariableNode)sourceNode;
                        var uaValue = await _uaClient.ReadUaValueAsync(sessionName, varNode);
                        result["value"] = uaValue.Value;
                        result["value-schema"] = JObject.Parse(uaValue.Schema.ToString());
                        result["status"] = uaValue.StatusCode?.ToString() ?? "";
                        result["deadBand"] = await _uaClient.GetDeadBandAsync(sessionName, varNode);
                        result["minimumSamplingInterval"] = varNode.MinimumSamplingInterval;
                        break;
                    case NodeClass.Object:
                        
                        if (await _uaClient.IsFolderTypeAsync(sessionName, decodedNodeId))
                        {
                            result["type"] = "folder";
                        }
                        else
                        {
                            result["type"] = "object";
                        }
                        break;
                }

                var linkedNodes = new JArray();
                var refDescriptions = await _uaClient.BrowseAsync(sessionName, decodedNodeId);
                foreach (var rd in refDescriptions)
                {
                    var refTypeNode = await _uaClient.ReadNodeAsync(sessionName, rd.ReferenceTypeId);
                    var targetNode = new JObject
                    {
                        ["node-id"] = rd.PlatformNodeId,
                        ["name"] = rd.DisplayName
                    };


                    switch (rd.NodeClass)
                    {
                        case NodeClass.Variable:
                            targetNode["Type"] = "variable";
                            break;
                        case NodeClass.Method:
                            targetNode["Type"] = "method";
                            break;
                        
                        case NodeClass.Object:
                            if (await _uaClient.IsFolderTypeAsync(sessionName, rd.PlatformNodeId))
                            {
                                targetNode["Type"] = "folder";
                            }
                            else
                            {
                                targetNode["Type"] = "object";
                            }
                            
                            break;
                        default:
                            throw new ArgumentOutOfRangeException();
                    }

                    targetNode["relationship"] = refTypeNode.DisplayName.Text;

                    linkedNodes.Add(targetNode);
                }

                result["edges"] = linkedNodes;
            }
            catch (ServiceResultException exc)
            {
                switch (exc.StatusCode)
                {
                    case StatusCodes.BadNodeIdUnknown:
                        return NotFound(new
                        {
                            error = "Wrong ID: There is no Resource with ID " + decodedNodeId
                        });
                    case StatusCodes.BadNodeIdInvalid:
                        return BadRequest(new
                        {
                            error = "Provided ID is invalid"
                        });
                    case StatusCodes.BadSessionIdInvalid:
                    case StatusCodes.BadSessionClosed:
                    case StatusCodes.BadSessionNotActivated:
                    case StatusCodes.BadTooManySessions:
                        return StatusCode(500, new
                        {
                            error = "Connection Lost"
                        });
                    default:
                        return StatusCode(500, new
                        {
                            error = exc.Message
                        });
                }
            }
            catch (SessionNotAvailableException)
            {
                return StatusCode(500, "the session " + sessionName + " NotAvailable");
            }

            return Ok(result);
        }
        #endregion

        #region Subscription Management
        [HttpPost("sessions/{sessionName}/monitor")]
        public async Task<IActionResult> Monitor(string sessionName, [FromBody] MonitorParams monitorParams)
        {
     

            if (monitorParams == null || !monitorParams.IsValid())
            {
                return BadRequest(new
                {
                    error = "Bad parameters format."
                });
            }

            if (!monitorParams.IsTelemetryProtocolSupported())
            {
                return BadRequest(new
                {
                    error = "Telemetry protocol provided in the broker url is not supported by the platform."
                });
            }

            foreach (var monitorableNode in monitorParams.MonitorableNodes)
            {
                if (!new List<string> { "Absolute", "Percent", "None" }.Contains(monitorableNode.DeadBand))
                {
                    return BadRequest(new
                    {
                        error = $"Value not allowed for DeadBand parameter. Found '{monitorableNode.DeadBand}'"
                    });
                }
            }

            
            if (!(await _uaClient.CheckSession(sessionName)))
                return StatusCode(500, "session " + sessionName + " NotAvailable");

            bool[] results;
            try
            {
                results = await _uaClient.CreateMonitoredItemsAsync(sessionName,
                    monitorParams.MonitorableNodes,
                    monitorParams.BrokerUrl,
                    monitorParams.Topic);
            }
            catch (ServiceResultException exc)
            {
                switch (exc.StatusCode)
                {
                    case StatusCodes.BadNodeIdUnknown:
                        return NotFound("There is no node with the specified Node Id");
                    case StatusCodes.BadNodeIdInvalid:
                        return BadRequest("Provided Node Id is invalid");
                    case StatusCodes.BadSessionIdInvalid:
                    case StatusCodes.BadSessionClosed:
                    case StatusCodes.BadSessionNotActivated:
                    case StatusCodes.BadTooManySessions:
                        return StatusCode(500, new
                        {
                            error = "Connection Lost"
                        });
                    default:
                        return StatusCode(500, exc.Message);
                }
            }
            catch (SessionNotAvailableException)
            {
                return StatusCode(500, "session " + sessionName + " NotAvailable");
            }


            return Ok(new
            {
                results
            });
        }
        [HttpPost("data-sets/{ds_id:int}/stop-monitor")]
        public async Task<IActionResult> StopMonitor(int ds_id, [FromBody] StopMonitorParams stopMonitorParams)
        {
            if (ds_id < 0 || ds_id >= _uaServers.Length) return NotFound($"There is no Data Set for id {ds_id}");

            if (stopMonitorParams == null || !stopMonitorParams.IsValid())
            {
                return BadRequest(new
                {
                    error = "Bad parameters format."
                });
            }

            var serverUrl = _uaServers[ds_id].Url;
            var result = await _uaClient.DeleteMonitoringPublish(serverUrl, stopMonitorParams.BrokerUrl,
                    stopMonitorParams.Topic);

            if (result)
            {
                return Ok($"Successfully stop monitoring  on broker {stopMonitorParams.BrokerUrl}.");
            }

            return BadRequest(new
            {
                error = $"An error occurred trying to delete the topic {stopMonitorParams.Topic} on broker {stopMonitorParams.BrokerUrl}. " +
                        $"Maybe there is no current monitoring for such parameters or an internal error occurred in the Data Set."
            });
        }
        #endregion

        #region Write 
        [HttpPost("sessions/{sessionName}/nodes/{node_id:regex(^\\d+-(?:(\\d+)|(.+))$)?}/writeValue")]
        public async Task<IActionResult> PostNodeAsync(string sessionName, string node_id, [FromBody] VariableState state)
        {
            if (state == null || !state.IsValid)
                return BadRequest(new
                {
                    error = "Insert a valid state for a Variable Node."
                });


            if (!(await _uaClient.CheckSession(sessionName)))
                return StatusCode(500, new
                {
                    error = "Session "+ sessionName+ " NotAvailable"
                });

            var decodedNodeId = WebUtility.UrlDecode(node_id);

            Node sourceNode;
            try
            {
                sourceNode = await _uaClient.ReadNodeAsync(sessionName, decodedNodeId);
            }
            catch (ServiceResultException exc)
            {
                switch (exc.StatusCode)
                {
                    case StatusCodes.BadNodeIdUnknown:
                        return NotFound(new
                        {
                            error = "Wrong ID: There is no Resource with ID " + decodedNodeId
                        });
                    case StatusCodes.BadNodeIdInvalid:
                        return BadRequest(new
                        {
                            error = "Provided ID is invalid"
                        });
                    case StatusCodes.BadSessionIdInvalid:
                    case StatusCodes.BadSessionClosed:
                    case StatusCodes.BadSessionNotActivated:
                    case StatusCodes.BadTooManySessions:
                        return StatusCode(500, new
                        {
                            error = "Connection Lost"
                        });
                    default:
                        return StatusCode(500, new
                        {
                            error = exc.Message
                        });
                }
            }
            catch (SessionNotAvailableException)
            {
                return StatusCode(500, new
                {
                    error = "Session" + sessionName + " NotAvailable"
                });
            }

            if (sourceNode.NodeClass != NodeClass.Variable)
                return BadRequest(new
                {
                    error = "There is no Value for the Node specified by the NodeId " + node_id
                });

            VariableNode variableNode = (VariableNode)sourceNode;

            try
            {
                await _uaClient.WriteNodeValueAsync(sessionName, variableNode, state);
            }
            catch (ValueToWriteTypeException exc)
            {
                return BadRequest(new
                {
                    error = exc.Message
                });
            }
            catch (NotImplementedException exc)
            {
                return StatusCode(500, new
                {
                    error = exc.Message
                });
            }
            catch (ServiceResultException exc)
            {
                switch (exc.StatusCode)
                {
                    case (StatusCodes.BadTypeMismatch):
                        return BadRequest(new
                        {
                            error = "Wrong Type - Check data and try again"
                        });
                    case StatusCodes.BadSessionIdInvalid:
                    case StatusCodes.BadSessionClosed:
                    case StatusCodes.BadSessionNotActivated:
                    case StatusCodes.BadTooManySessions:
                        return StatusCode(500, new
                        {
                            error = "Connection Lost"
                        });
                    default:
                        return BadRequest(new
                        {
                            error = exc.Message
                        });
                }

            }
            return Ok("Write on Node {node_id} in the Data Set {ds_id} executed.");
        }

        [HttpPost("sessions/{sessionName}/writeValues")]
        public async Task<IActionResult> PostNodesAsync(string sessionName, [FromBody]WriteParameters writeParam)
        {
            foreach (var state in writeParam.listOfVaribleState)
            {
                if (state == null || !state.IsValid)
                    return BadRequest(new
                    {
                        error = "Insert a valid value for a Variable Node."
                    });
            }

      

            
            if (!(await _uaClient.CheckSession(sessionName)))
                return StatusCode(500, new
                {
                    error = "Session " + sessionName + " NotAvailable"
                });

            List<string> listOfNodeId = new List<string>();
            foreach (var node_id in writeParam.listOfNodeId)
            {
                var decodedNodeId = WebUtility.UrlDecode(node_id);
                listOfNodeId.Add(decodedNodeId);
            }

            List<Node> sourceNodes = new List<Node>();
            Node sourceNode;
            foreach (var decodedNodeId in listOfNodeId)
            {
                try
                {

                    sourceNode = await _uaClient.ReadNodeAsync(sessionName, decodedNodeId);

                    if (sourceNode.NodeClass != NodeClass.Variable)
                        return BadRequest(new
                        {
                            error = "There is no Value for the Node specified by the NodeId " + decodedNodeId
                        });

                    sourceNodes.Add(sourceNode);

                }
                catch (ServiceResultException exc)
                {
                    switch (exc.StatusCode)
                    {
                        case StatusCodes.BadNodeIdUnknown:
                            return NotFound(new
                            {
                                error = "Wrong ID: There is no Resource with ID " + decodedNodeId
                            });
                        case StatusCodes.BadNodeIdInvalid:
                            return BadRequest(new
                            {
                                error = "Provided ID is invalid"
                            });
                        case StatusCodes.BadSessionIdInvalid:
                        case StatusCodes.BadSessionClosed:
                        case StatusCodes.BadSessionNotActivated:
                        case StatusCodes.BadTooManySessions:
                            return StatusCode(500, new
                            {
                                error = "Connection Lost"
                            });
                        default:
                            return StatusCode(500, new
                            {
                                error = exc.Message
                            });
                    }
                }
                catch (SessionNotAvailableException)
                {
                    return StatusCode(500, new
                    {
                        error = "Session " + sessionName + " NotAvailable"
                    });
                }
            }


            List<VariableNode> variablesNode = new List<VariableNode>();
            foreach (var node in sourceNodes)
            {
                VariableNode variableNode = (VariableNode)node;
                variablesNode.Add(variableNode);
            }


            try
            {
                await _uaClient.WriteNodeValuesAsync(sessionName, variablesNode, writeParam.listOfVaribleState);
            }
            catch (ValueToWriteTypeException exc)
            {
                return BadRequest(new
                {
                    error = exc.Message
                });
            }
            catch (NotImplementedException exc)
            {
                return StatusCode(500, new
                {
                    error = exc.Message
                });
            }
            catch (ServiceResultException exc)
            {
                switch (exc.StatusCode)
                {
                    case (StatusCodes.BadTypeMismatch):
                        return BadRequest(new
                        {
                            error = "Wrong Type - Check data and try again"
                        });
                    case StatusCodes.BadSessionIdInvalid:
                    case StatusCodes.BadSessionClosed:
                    case StatusCodes.BadSessionNotActivated:
                    case StatusCodes.BadTooManySessions:
                        return StatusCode(500, new
                        {
                            error = "Connection Lost"
                        });
                    default:
                        return BadRequest(new
                        {
                            error = exc.Message
                        });
                }

            }
            return Ok("Write on Node {node_id} in the Data Set {ds_id} executed.");

        }
        #endregion


        #region Read History
        [HttpPost("data-sets/{ds_id:int}/ReadRaw")]
        public async Task<IActionResult> ReadRawNodes(int ds_id, [FromBody]ReadRawParameters readRawParam)
        {
            if (readRawParam == null || !readRawParam.IsValid())
                return BadRequest(new
                {
                    error = "Insert a valid state for a Variable Node."
                });

            if (ds_id < 0 || ds_id >= _uaServers.Length) return NotFound($"There is no Data Set for id {ds_id}");

            var serverUrl = _uaServers[ds_id].Url;
            if (!(await _uaClient.IsServerAvailable(serverUrl)))
                return StatusCode(500, new
                {
                    error = "Data Set " + ds_id + " NotAvailable"
                });
            var result = await _uaClient.ReadRaw(serverUrl, readRawParam.bIsReadModified, Convert.ToDateTime(readRawParam.dateStartDateTime), Convert.ToDateTime(readRawParam.dateEndDateTime), readRawParam.iMaxReturnVal, readRawParam.lstNodeId);
            return Ok(result);
        }
        #endregion



        

       

        [HttpGet("/data-sets/{id}/machine")]
        public async Task <IActionResult>GetEndpoints(string id)
        {
            try
            {
                if (id.Equals(string.Empty))
                {
                    return BadRequest(new
                    {
                        error = "Bad parameters format."
                    });
                }
               var listOfEndpoints= await _uaClient.GetEndpoints(id);
                return Ok(listOfEndpoints);


            }
            catch(Exception e)
            {
                return BadRequest(new
                {
                    error = $"One or more error occured : {e.Message}"
                }) ;
            }
        }

      
    }
}
