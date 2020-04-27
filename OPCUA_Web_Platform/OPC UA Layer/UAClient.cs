using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using WebPlatform.Extensions;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using WebPlatform.Models.OPCUA;
using WebPlatform.Exceptions;
using WebPlatform.Monitoring;
using WebPlatform.Models.DataSet;
using WebPlatform.OPC_UA_Layer;
using IntegrationObjects.Opc.Ua.Utilities;
using System.Security.Cryptography.X509Certificates;

namespace WebPlatform.OPCUALayer
{
    public interface IUaClient
    {
        Task<Node> ReadNodeAsync(string serverUrl, string nodeIdStr);
        Task<Node> ReadNodeAsync(string serverUrl, NodeId nodeId);
        Task<IEnumerable<EdgeDescription>> BrowseAsync(string serverUrl, string nodeToBrowseIdStr);
        Task<UaValue> ReadUaValueAsync(string serverUrl, VariableNode varNode);
        Task<List<OPCUATag>> ReadRaw(string serverUrl, bool bIsReadModified, DateTime dateStartDateTime, DateTime dateEndDateTime, int iMaxReturnVal, List<string> lstNodeId);
        Task<string> GetDeadBandAsync(string serverUrl, VariableNode varNode);
        Task<bool> WriteNodeValueAsync(string serverUrl, VariableNode variableNode, VariableState state);
        Task<bool> WriteNodeValuesAsync(string serverUrl, List<VariableNode> variableNode, List<VariableState> state);
        Task<bool> IsFolderTypeAsync(string serverUrlstring, string nodeIdStr);
        Task<bool> IsServerAvailable(string serverUrlstring);
        Task <Session>CreateSession(OPCUAServer server,string sessionName);
        Task<bool[]> CreateMonitoredItemsAsync(string sessionName, MonitorableNode[] monitorableNodes, string brokerUrl, string topic);
        Task<bool> DeleteMonitoringPublish(string serverUrl, string brokerUrl, string topic);
        Task<List<string>> GetEndpoints(string strHostName);
        Task<bool> CheckSession(string session);
    }

    public interface IUaClientSingleton : IUaClient {}

    public class UaClient : IUaClientSingleton
    {
        private readonly ApplicationInstance _application;
        private ApplicationConfiguration _appConfiguration;
        private bool _autoAccept;

        //A Dictionary containing al the active Sessions, indexed per server Id.
       // private readonly Dictionary<string, Session> _sessions;
        private readonly Dictionary<string, List<MonitorPublishInfo>> _monitorPublishInfo;
        private Dictionary<string, Session> dicOfSession = new Dictionary<string, Session>();

        public UaClient()
        {
            _application = new ApplicationInstance
            {
                ApplicationType = ApplicationType.Client,
                ConfigSectionName = "OPCUAWebPlatform"
            };

            dicOfSession = new Dictionary<string, Session>();
            _monitorPublishInfo = new Dictionary<string, List<MonitorPublishInfo>>();
        }

        public async Task<Node> ReadNodeAsync(string serverUrl, string nodeIdStr)
        {
           
            try
            {
                Session session = await GetSessionAsync(serverUrl);
                NodeId nodeToRead = PlatformUtils.ParsePlatformNodeIdString(nodeIdStr);
                var node = session.ReadNode(nodeToRead);
                return node;
            }catch(Exception e)
            {
                return null;
            }
        }

        public async Task<Node> ReadNodeAsync(string serverUrl, NodeId nodeToRead)
        {
            Session session = await GetSessionAsync(serverUrl);
            Node node;
            node = session.ReadNode(nodeToRead);
            return node;
        }


        public async Task<bool> WriteNodeValueAsync(string serverUrl, VariableNode variableNode, VariableState state)
        {
            Session session = await GetSessionAsync(serverUrl);
            var typeManager = new DataTypeManager(session);
            WriteValueCollection writeValues = new WriteValueCollection();
            
            WriteValue writeValue = new WriteValue
            {
                NodeId = variableNode.NodeId,
                AttributeId = Attributes.Value,
                Value = typeManager.GetDataValueFromVariableState(state, variableNode)
            };

            writeValues.Add(writeValue);

            session.Write(null, writeValues, out var results, out _);
            if (!StatusCode.IsGood(results[0])) {
                if (results[0] == StatusCodes.BadTypeMismatch)
                    throw new ValueToWriteTypeException("Wrong Type Error: data sent are not of the type expected. Check your data and try again");
                throw new ValueToWriteTypeException(results[0].ToString());
            }
            return true;
        }


        public async Task<bool> WriteNodeValuesAsync(string serverUrl, List<VariableNode> variableNode, List<VariableState> state)
        {
            Session session = await GetSessionAsync(serverUrl);
            var typeManager = new DataTypeManager(session);
            WriteValueCollection writeValues = new WriteValueCollection();

            for(int i=0;i< variableNode.Count;i++)
            {
                WriteValue writeValue = new WriteValue
                {
                    NodeId = variableNode[i].NodeId,
                    AttributeId = Attributes.Value,
                    Value = typeManager.GetDataValueFromVariableState(state[i], variableNode[i])
                };

                writeValues.Add(writeValue);
            }

            session.Write(null, writeValues, out var results, out _);
            if (!StatusCode.IsGood(results[0]))
            {
                if (results[0] == StatusCodes.BadTypeMismatch)
                    throw new ValueToWriteTypeException("Wrong Type Error: data sent are not of the type expected. Check your data and try again");
                throw new ValueToWriteTypeException(results[0].ToString());
            }
            return true;
        }

        public async Task<IEnumerable<EdgeDescription>> BrowseAsync(string serverUrl, string nodeToBrowseIdStr)
        {
            Session session = await GetSessionAsync(serverUrl);
            NodeId nodeToBrowseId = PlatformUtils.ParsePlatformNodeIdString(nodeToBrowseIdStr);

            var browser = new Browser(session)
            {
                NodeClassMask = (int)NodeClass.Method | (int)NodeClass.Object| (int)NodeClass.Variable,
                ResultMask = (uint)BrowseResultMask.DisplayName | (uint)BrowseResultMask.NodeClass | (uint)BrowseResultMask.ReferenceTypeInfo,
                BrowseDirection = BrowseDirection.Forward,
                ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences
            };

            return browser.Browse(nodeToBrowseId)
                .Select(rd => new EdgeDescription(rd.NodeId.ToStringId(session.MessageContext.NamespaceUris), 
                    rd.DisplayName.Text, 
                    rd.NodeClass, 
                    rd.ReferenceTypeId));
        }

        public async Task<bool> IsFolderTypeAsync(string serverUrl, string nodeIdStr)
        {
            try
            {
                Session session = await GetSessionAsync(serverUrl);
                NodeId nodeToBrowseId = PlatformUtils.ParsePlatformNodeIdString(nodeIdStr);

                //Set a Browser object to follow HasTypeDefinition Reference only
                var browser = new Browser(session)
                {
                    ResultMask = (uint)BrowseResultMask.DisplayName | (uint)BrowseResultMask.TargetInfo,
                    BrowseDirection = BrowseDirection.Forward,
                    ReferenceTypeId = ReferenceTypeIds.HasTypeDefinition
                };

                var descriptionCollection = browser.Browse(nodeToBrowseId);
                //islem 
                if (descriptionCollection.Count > 0)
                {
                    ReferenceDescription refDescription = browser.Browse(nodeToBrowseId)[0];
                    NodeId targetId = ExpandedNodeId.ToNodeId(refDescription.NodeId, session.MessageContext.NamespaceUris);

                    //Once got the Object Type, set the browser to follow Type hierarchy in inverse order.
                    browser.ReferenceTypeId = ReferenceTypeIds.HasSubtype;
                    browser.BrowseDirection = BrowseDirection.Inverse;

                    while (targetId != ObjectTypeIds.FolderType && targetId != ObjectTypeIds.BaseObjectType)
                    {
                        refDescription = browser.Browse(targetId)[0];
                        targetId = ExpandedNodeId.ToNodeId(refDescription.NodeId, session.MessageContext.NamespaceUris);
                    }
                    return targetId == ObjectTypeIds.FolderType;
                }
                else
                {
                    return false;
                }
            }catch(Exception e)
            {
                return false;
            }
        }

        public async Task<UaValue> ReadUaValueAsync(string serverUrl, VariableNode variableNode)
        {
            Session session = await GetSessionAsync(serverUrl);
            var typeManager = new DataTypeManager(session);

            return typeManager.GetUaValue(variableNode);
        }

        public async Task<List<OPCUATag>> ReadRaw(string serverUrl, bool bIsReadModified, DateTime dateStartDateTime, DateTime dateEndDateTime, int iMaxReturnVal, List<string> lstNodeId)
        {
            List<OPCUATag> tags = new List<OPCUATag>();
            HistoryReadResultCollection objHistoryReadResult = new HistoryReadResultCollection();
            try
            {
               
               
                Session session = await GetSessionAsync(serverUrl);
                ReadRawModifiedDetails details = new ReadRawModifiedDetails();
                details.StartTime = DateTime.MinValue;
                details.EndTime = DateTime.MinValue;
                details.IsReadModified = bIsReadModified;
                details.NumValuesPerNode = 0;

                details.StartTime = dateStartDateTime.ToUniversalTime();

                details.EndTime = dateEndDateTime.ToUniversalTime();

                details.NumValuesPerNode = (uint)iMaxReturnVal;

                HistoryReadValueIdCollection nodesToRead = new HistoryReadValueIdCollection();

                foreach (string strNodeId in lstNodeId)//OA-2018-03-13
                {
                    HistoryReadValueId nodeToRead = new HistoryReadValueId();

                    nodeToRead.NodeId = (NodeId)strNodeId;//_reference.NodeId;

                    nodesToRead.Add(nodeToRead);
                }
                HistoryReadResultCollection HistoryResults = null;
                DiagnosticInfoCollection diagnosticInfos = null;

                session.HistoryRead(
                    null,
                    new ExtensionObject(details),
                    TimestampsToReturn.Source,
                    false,
                    nodesToRead,
                    out HistoryResults,
                    out diagnosticInfos);

                Session.ValidateResponse(HistoryResults, nodesToRead);
                Session.ValidateDiagnosticInfos(diagnosticInfos, nodesToRead);

                #region Prepare result 
                objHistoryReadResult = HistoryResults;
                if (objHistoryReadResult.Count > 0)
                {
                    var m_index = 0;
                    foreach (var result in objHistoryReadResult)
                    {
                        HistoryData results = ExtensionObject.ToEncodeable(result.HistoryData) as HistoryData;
                        if (results == null)
                        {
                            return tags;
                        }
                        for (int ii = 0; ii < results.DataValues.Count; ii++)
                        {
                            StatusCode status = results.DataValues[ii].StatusCode;
                            string index = Utils.Format("[{0}]", m_index++);
                            var timestamp = results.DataValues[ii].SourceTimestamp.ToLocalTime();
                            var sec = results.DataValues[ii].SourceTimestamp.Millisecond;
                            string value = Utils.Format("{0}", results.DataValues[ii].WrappedValue);
                            string quality = Utils.Format("{0}", (StatusCode)status.CodeBits);
                            string historyInfo = Utils.Format("{0:X2}", (int)status.AggregateBits);
                            var date = String.Format("{0}.{1}", timestamp.ToString("MM/dd/yyyy HH:mm:ss"), sec.ToString().PadLeft(3, '0'));
                            OPCUATag tag = new OPCUATag(index, date, value, quality);

                            tags.Add(tag);


                        }
                    }
                }
                #endregion

                return tags;
            }
            catch(Exception e)
            {
                return tags;
            }


        }

        public async Task<bool> IsServerAvailable(string serverUrlstring)
        {
            Session session;
            try
            {
                session = await GetSessionAsync(serverUrlstring);
            }
            catch (Exception exc)
            {
                return false;
            }
            if(session.IsServerStatusGood())
                return true;
            return await RestoreSessionAsync(serverUrlstring);
        }
             
        
        public async Task<string> GetDeadBandAsync(string serverUrl, VariableNode varNode)
        {
            Session session = await GetSessionAsync(serverUrl);
            var dataTypeId = varNode.DataType;

            var browse = new Browser(session)
            {
                ResultMask = (uint) BrowseResultMask.TargetInfo,
                BrowseDirection = BrowseDirection.Inverse,
                ReferenceTypeId = ReferenceTypeIds.HasSubtype
            };
            
            while (!(dataTypeId.Equals(DataTypeIds.Number)) && !(dataTypeId.Equals(DataTypeIds.BaseDataType)))
            {
                dataTypeId = ExpandedNodeId.ToNodeId(browse.Browse(dataTypeId)[0].NodeId, session.MessageContext.NamespaceUris);
            }

            var isAbsolute = (dataTypeId == DataTypeIds.Number);
            
            browse.BrowseDirection = BrowseDirection.Forward;
            browse.ReferenceTypeId = ReferenceTypeIds.HasProperty;
            var rdc = browse.Browse(varNode.NodeId);

            var isPercent = rdc.Exists(rd => rd.BrowseName.Name.Equals("EURange"));
            
            if (isAbsolute)
            {
                return isPercent ? "Absolute, Percentage" : "Absolute";
            }

            return isPercent ? "Percentage" : "None";

        }

        public async Task<bool[]> CreateMonitoredItemsAsync(string sessionName, MonitorableNode[] monitorableNodes,
            string brokerUrl, string topic)
        {
            var session = await GetSessionAsync(sessionName);

            MonitorPublishInfo monitorInfo;

            const string pattern = @"^(mqtt|signalr):(.*)$";
            var match = Regex.Match(brokerUrl, pattern);
            var protocol = match.Groups[1].Value;
            var url = match.Groups[2].Value;
            
            var publisher = PublisherFactory.GetPublisherForProtocol(protocol, url);
            
            //Set publishInterval to minimum samplinginterval
            var publishInterval = monitorableNodes.Select(elem => elem.SamplingInterval).Min();

            lock (_monitorPublishInfo)
            {
                //Check if a Subscription for the
                if (_monitorPublishInfo.ContainsKey(sessionName))
                {
                    monitorInfo = _monitorPublishInfo[sessionName].FirstOrDefault(info => info.Topic == topic && info.BrokerUrl == url);
                    if (monitorInfo == null)
                    {
                        monitorInfo = new MonitorPublishInfo()
                        {
                            Topic = topic,
                            BrokerUrl = url,
                            Subscription = CreateSubscription(session, publishInterval, 0),
                            Publisher = publisher
                        };
                        _monitorPublishInfo[sessionName].Add(monitorInfo);
                    }
                    else if (monitorInfo.Subscription.PublishingInterval > publishInterval)
                    {
                        monitorInfo.Subscription.PublishingInterval = publishInterval;
                        monitorInfo.Subscription.Modify();
                    }
                }
                else
                {
                    monitorInfo = new MonitorPublishInfo()
                    {
                        Topic = topic,
                        BrokerUrl = url,
                        Subscription = CreateSubscription(session, publishInterval, 0),
                        Publisher = publisher
                    };
                    var list = new List<MonitorPublishInfo> { monitorInfo };
                    _monitorPublishInfo.Add(sessionName, list);
                }
            }

            var createdMonitoredItems = new List<MonitoredItem>();

            foreach (var monitorableNode in monitorableNodes)
            {
                var mi = new MonitoredItem()
                {
                    StartNodeId = PlatformUtils.ParsePlatformNodeIdString(monitorableNode.NodeId),
                    DisplayName = monitorableNode.NodeId,
                    SamplingInterval = monitorableNode.SamplingInterval
                };

                if (monitorableNode.DeadBand != "none")
                {
                    mi.Filter = new DataChangeFilter()
                    {
                        Trigger = DataChangeTrigger.StatusValue,
                        DeadbandType = (uint)(DeadbandType)Enum.Parse(typeof(DeadbandType), monitorableNode.DeadBand, true),
                        DeadbandValue = monitorableNode.DeadBandValue
                    };
                }

                mi.Notification += OnMonitorNotification;
                monitorInfo.Subscription.AddItem(mi);
                var monitoredItems = monitorInfo.Subscription.CreateItems();
                createdMonitoredItems.AddRange(monitoredItems);
            }
            
            var results = createdMonitoredItems.Distinct().Select(m => m.Created).ToArray();
            foreach (var monitoredItem in createdMonitoredItems.Where(m => !m.Created))
            {
                monitorInfo.Subscription.RemoveItem(monitoredItem);
            }

            return results;
        }

        public async Task<bool> DeleteMonitoringPublish(string serverUrl, string brokerUrl, string topic)
        {
            var session = await GetSessionAsync(serverUrl);

            lock (_monitorPublishInfo)
            {
                if (!_monitorPublishInfo.ContainsKey(serverUrl)) return false;
            
                const string pattern = @"^(mqtt|signalr):(.*)$";
                var match = Regex.Match(brokerUrl, pattern);
                brokerUrl = match.Groups[2].Value;
            
                var monitorPublishInfo = _monitorPublishInfo[serverUrl].Find(mpi => mpi.Topic == topic && mpi.BrokerUrl == brokerUrl);

                if (monitorPublishInfo == null) return false;
            
                try
                {
                    session.DeleteSubscriptions(null, new UInt32Collection(new[] {monitorPublishInfo.Subscription.Id}), out var _, out var _);
                }
                catch (ServiceResultException e)
                {
                    Console.WriteLine(e);
                    return false;
                }
            
                _monitorPublishInfo[serverUrl].Remove(monitorPublishInfo);
                if (_monitorPublishInfo[serverUrl].Count == 0) _monitorPublishInfo.Remove(serverUrl);
                
                Console.WriteLine($"Deleted Subscription {monitorPublishInfo.Subscription.Id} for the topic {topic}.");
            }
            
            return true;
        }

        #region private methods

        private void OnMonitorNotification(MonitoredItem monitoreditem, MonitoredItemNotificationEventArgs e)
        {
            VariableNode varNode = (VariableNode)monitoreditem.Subscription.Session.ReadNode(monitoreditem.StartNodeId);
            foreach (var value in monitoreditem.DequeueValues())
            {
                Console.WriteLine("Got a value");
                var typeManager = new DataTypeManager(monitoreditem.Subscription.Session);
                UaValue opcvalue = typeManager.GetUaValue(varNode, value, false);

                dynamic monitorInfoPair;

                lock (_monitorPublishInfo)
                {
                    monitorInfoPair = _monitorPublishInfo
                        .SelectMany(pair => pair.Value, (parent, child) => new { ServerUrl = parent.Key, Info = child })
                        .First(couple => couple.Info.Subscription == monitoreditem.Subscription);
                }

                var message = $"[TOPIC: /*{monitorInfoPair.Info.Topic}]*/  \t ({monitoreditem.DisplayName}):{opcvalue.Value}";
                monitorInfoPair.Info.Forward(message);
                Console.WriteLine(message);
            }
        }

        private static Subscription CreateSubscription(Session session, int publishingInterval, uint maxNotificationPerPublish)
        {
            var sub = new Subscription(session.DefaultSubscription)
            {
                PublishingInterval = publishingInterval,
                MaxNotificationsPerPublish = maxNotificationPerPublish
            };

            if (!session.AddSubscription(sub)) return null;
            sub.Create();
            return sub;

        }

        /// <summary>
        /// This method is called when a OPC UA Service call in a session object returns an error 
        /// </summary>
        /// <param name="serverUrlstring"></param>
        /// <returns></returns>
        private async Task<bool> RestoreSessionAsync(string serverUrlstring)
        {
            lock (dicOfSession)
            {
                if(dicOfSession.ContainsKey(serverUrlstring))
                    dicOfSession.Remove(serverUrlstring);
            }

            Session session;
            try
            {
                return (await GetSessionAsync(serverUrlstring)).IsServerStatusGood();
            }
            catch (Exception)
            {
                return false;
            }
        }



        private async Task<Session> GetSessionAsync(string sessionName)
        {
            
            try
            {
                if (dicOfSession.ContainsKey(sessionName)) return dicOfSession[sessionName];
                else throw new SessionNotAvailableException();



            }
            catch (Exception)
            {
                throw new SessionNotAvailableException();
            }
            
           

            
        }

      


        private async Task CheckAndLoadConfiguration()
        {
            if (_appConfiguration == null)
            {
                _appConfiguration = await _application.LoadApplicationConfiguration(false);
                
                var haveAppCertificate = await _application.CheckApplicationInstanceCertificate(false, 0);
                if (!haveAppCertificate)
                {
                    throw new Exception("Application instance certificate invalid!");
                }

                _appConfiguration.ApplicationUri =
                    Utils.GetApplicationUriFromCertificate(_appConfiguration.SecurityConfiguration.ApplicationCertificate
                        .Certificate);
                if (_appConfiguration.SecurityConfiguration.AutoAcceptUntrustedCertificates)
                {
                    _autoAccept = true;
                }

                _appConfiguration.CertificateValidator.CertificateValidation += CertificateValidator_CertificateValidation;
            }
        }

        private void CertificateValidator_CertificateValidation(CertificateValidator sender, CertificateValidationEventArgs e)
        {
            if (e.Error.StatusCode == StatusCodes.BadCertificateUntrusted)
            {
                e.Accept = _autoAccept;
                Console.WriteLine(_autoAccept ? "Accepted Certificate: {0}" : "Rejected Certificate: {0}",
                    e.Certificate.Subject);
            }
        }

        public async Task<List<string>> GetEndpoints(string strHostName)
        {
            List<string> DiscoveredUrls = new List<string>();
            ApplicationDescriptionCollection servers;
            try
            {
                await CheckAndLoadConfiguration();
                EndpointConfiguration configuration = EndpointConfiguration.Create(_appConfiguration);
                configuration.OperationTimeout = 20000;
                using (DiscoveryClient client = DiscoveryClient.Create(new Uri(Utils.Format("opc.tcp://{0}:4840", strHostName)), configuration))
                {
                    // ApplicationDescriptionCollection
                    servers = client.FindServers(null);

                    // populate the drop down list with the discovery URLs for the available servers.
                    for (int ii = 0; ii < servers.Count; ii++)
                    {
                        // don't show discovery servers.
                        if (servers[ii].ApplicationType == ApplicationType.DiscoveryServer)
                        {
                            continue;
                        }

                        for (int jj = 0; jj < servers[ii].DiscoveryUrls.Count; jj++)
                        {
                            string discoveryUrl = servers[ii].DiscoveryUrls[jj];

                            // Many servers will use the '/discovery' suffix for the discovery endpoint.
                            // The URL without this prefix should be the base URL for the server. 
                            if (discoveryUrl.EndsWith("/discovery"))
                            {
                                discoveryUrl = discoveryUrl.Substring(0, discoveryUrl.Length - "/discovery".Length);
                            }

                            // remove duplicates.
                            if (!DiscoveredUrls.Contains(discoveryUrl))
                            {
                                DiscoveredUrls.Add(discoveryUrl);
                            }
                        }
                    }
                }

                //lstDiscoveredUrls = DiscoveredUrls;
                return DiscoveredUrls;

            }
            catch(Exception ex)
            {
                string str = String.Format("Failed to get the endpoints. Exception: {0}", ex.Message);
                return DiscoveredUrls;
            }
           
        }

        public async Task <Session>CreateSession(OPCUAServer server, string sessionName)
        {
            try
            {
                lock (dicOfSession)
                {
                    if (dicOfSession.ContainsKey(sessionName)) return dicOfSession[sessionName];
                }


                #region OPCUAServer
                UAServer objUAServer = new UAServer();
                objUAServer.Protocol = server.protocol;
                objUAServer.SecurityMode = server.securityMode;
                objUAServer.SecurityPolicy = server.securityMode;
                objUAServer.SecurityPolicy = server.securityPolicy;
                objUAServer.UserIdentityString = server.UserIdentityString;
                objUAServer.ServerName = server.serverName;
                try
                {
                    objUAServer.UserIdentity = (UserIdentityType)Enum.Parse(typeof(UserIdentityType), objUAServer.UserIdentityString);
                }
                catch
                {
                    if (objUAServer.UserIdentityString.Equals("Anonymous"))
                    {
                        objUAServer.UserIdentity = UserIdentityType.Anonymous;
                    }
                    else if (objUAServer.UserIdentityString.Equals("UserName"))
                    {
                        objUAServer.UserIdentity = UserIdentityType.UserName;
                    }
                    else
                    {
                        objUAServer.UserIdentity = UserIdentityType.Certificate;
                    }
                }

                if (objUAServer.UserIdentity.Equals(UserIdentityType.Certificate))
                {

                    objUAServer.IsSecurityStoreEnabled = false;
                    objUAServer.CertificationPath = server.certificationPath;
                    objUAServer.CertificationPassword = server.certificationPassword;


                }
                else if (objUAServer.UserIdentity.Equals(UserIdentityType.UserName))
                {

                    objUAServer.UserName = server.userName;
                    objUAServer.UserPassword = server.userPassword;

                }
                #endregion

                await CheckAndLoadConfiguration();

                // Create the configuration.
                ApplicationConfiguration configuration = _appConfiguration; // Helpers.CreateClientConfiguration(myServer);

                // Create the endpoint description.
                EndpointDescription endpointDescription = Helpers.CreateEndpointDescription(objUAServer);

                // Create the endpoint configuration (use the application configuration to provide default values).
                EndpointConfiguration endpointConfiguration = EndpointConfiguration.Create(configuration);

                // The default timeout for a requests sent using the channel.
                endpointConfiguration.OperationTimeout = 300000;

                // Use the pure binary encoding on the wire.
                //OA-2018-04-11
                // endpointConfiguration.UseBinaryEncoding = true;
                if (objUAServer.MessageEncoding.ToLower().Equals("binary"))
                {
                    endpointConfiguration.UseBinaryEncoding = true;
                }
                else
                {
                    endpointConfiguration.UseBinaryEncoding = false;
                }

                IUserIdentity identity;
                

                var t = _appConfiguration.SecurityConfiguration.ApplicationCertificate.Find(true);
                X509Certificate2 clientCertificate = t.Result;

                UserTokenPolicy poly;


                if (objUAServer.UserIdentity.Equals(UserIdentityType.UserName))
                {
                    identity = new UserIdentity(objUAServer.UserName, objUAServer.UserPassword);
                    poly = new UserTokenPolicy(UserTokenType.UserName);
                    //added by kais wali
                    bool exist = false;
                    foreach (UserTokenPolicy poltemp in endpointDescription.UserIdentityTokens)
                    {
                        if (poltemp.TokenType.ToString() == poly.TokenType.ToString())
                        {
                            exist = true;
                            break;
                        }
                    }
                    if (!exist)
                        endpointDescription.UserIdentityTokens.Add(poly);
                }
                else if (objUAServer.UserIdentity.Equals(UserIdentityType.Certificate))
                {
                    
                    CertificateIdentifier certificateIdentifier = new CertificateIdentifier();
                    X509Certificate2 currentCertificate;
                    certificateIdentifier.StoreType = CertificateStoreType.Directory;
                    currentCertificate = new X509Certificate2(objUAServer.CertificationPath, objUAServer.CertificationPassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                    if (currentCertificate == null)
                    {
                        throw ServiceResultException.Create(StatusCodes.BadCertificateInvalid, "Could not find certificate: {0}", certificateIdentifier.SubjectName);
                    }
                    identity = new UserIdentity(currentCertificate);
                    //

                    poly = new UserTokenPolicy(UserTokenType.Certificate);
                    //added by kais wali
                    bool exist = false;
                    foreach (UserTokenPolicy poltemp in endpointDescription.UserIdentityTokens)
                    {
                        if (poltemp.TokenType.ToString() == poly.TokenType.ToString())
                        {
                            exist = true;
                            break;
                        }
                    }
                    if (!exist)
                        endpointDescription.UserIdentityTokens.Add(poly);
                }
                else
                {
                    identity = new UserIdentity();
                    poly = new UserTokenPolicy(UserTokenType.Anonymous);
                    //added by kais wali
                    bool exist = false;
                    foreach (UserTokenPolicy poltemp in endpointDescription.UserIdentityTokens)
                    {
                        if (poltemp.TokenType.ToString() == poly.TokenType.ToString())
                        {
                            exist = true;
                            break;
                        }
                    }
                    if (!exist)
                        endpointDescription.UserIdentityTokens.Add(poly);
                }

                // Create the endpoint.
                ConfiguredEndpoint endpoint = new ConfiguredEndpoint(null, endpointDescription, endpointConfiguration);

                // Update endpoint description using the discovery endpoint.
                // create message context.
                ServiceMessageContext messageContext = configuration.CreateMessageContext();

                //Set to true in default configuration (If the user have not configured an OPC UA Server in the ONBS)
                endpoint.UpdateBeforeConnect = false;
                // update endpoint description using the discovery endpoint.

                //OA-2018-06-19 Commented
                /*if (endpoint.UpdateBeforeConnect)
                {
                    BindingFactory bindingFactory = BindingFactory.Create(configuration, messageContext);
                    endpoint.UpdateFromServer(bindingFactory);

                    endpointDescription = endpoint.Description;
                    endpointConfiguration = endpoint.Configuration;
                }*/

                // Set up a callback to handle certificate validation errors.
                //  configuration.CertificateValidator.CertificateValidation += new CertificateValidationEventHandler(CertificateValidator_CertificateValidation);


                // initialize the channel which will be created with the server.
                ITransportChannel channel = SessionChannel.Create(
                     configuration,
                     endpointDescription,
                     endpointConfiguration,
                     //clientCertificateChain,
                     clientCertificate,
                     messageContext);

                // create the session object.
                //OA-2017-08-15
                Session m_session = new Session(channel, configuration, endpoint, clientCertificate);
                //m_session = new Session(channel, configuration, endpoint, null);

                //OA-2017-09-20
                byte[] certificateData = endpoint.Description.ServerCertificate;
                //islem Commented serverCertificate
                if (certificateData != null) //OA-2018-04-27
                                             //serverCertificate = Utils.ParseCertificateBlob(certificateData);
                                             //

                    m_session.ReturnDiagnostics = DiagnosticsMasks.All;

                // Register keep alive callback.
                //islem Commented KeepAlive
                // m_session.KeepAlive += new KeepAliveEventHandler(Session_KeepAlive);

                // create the session.
                try
                {

                    m_session.Open(sessionName, 60000, identity, null);
                    dicOfSession.Add(sessionName, m_session);//OA-2017-09-20

                }
                catch (Exception e)
                {

                }

                return m_session;
            }
            catch(Exception e)
            {
                return null;
            }

        }

        public async Task<bool> CheckSession(string sessionName)
        {
            bool bsession = false;
            try
            {
                if (dicOfSession.ContainsKey(sessionName)) bsession=true;
                return bsession;

            }
            catch(Exception e)
            {
                return bsession;
            }
        }

        #endregion
    }
}