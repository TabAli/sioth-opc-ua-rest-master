using IntegrationObjects.Opc.Ua.Utilities;
using Opc.Ua;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace WebPlatform.OPC_UA_Layer
{
    partial class Helpers
    {
        public static EndpointDescription CreateEndpointDescription(UAServer myServer)
        {

            // create the endpoint description.
            EndpointDescription endpointDescription = null;

            try
            {
                

                string discoveryUrl = myServer.ServerName;
                //OA 2018-04-27
                if (!discoveryUrl.StartsWith(Utils.UriSchemeOpcTcp) && !discoveryUrl.StartsWith(Utils.UriSchemeHttps))
                //if (!discoveryUrl.StartsWith(Utils.UriSchemeOpcTcp))
                {
                    if (!discoveryUrl.EndsWith("/discovery"))
                    {
                        discoveryUrl += "/discovery";
                    }
                }

                // parse the selected URL.
                Uri uri = new Uri(discoveryUrl);

                // set a short timeout because this is happening in the drop down event.
                EndpointConfiguration configuration = EndpointConfiguration.Create();
                configuration.OperationTimeout = 5000;

                //OA 2018-04-27 https
                if (discoveryUrl.StartsWith(Utils.UriSchemeHttps))
                {
                    configuration.OperationTimeout = 0;
                }
                //

                // Connect to the server's discovery endpoint and find the available configuration.
                using (DiscoveryClient client = DiscoveryClient.Create(uri, configuration))
                {
                    EndpointDescriptionCollection endpoints = client.GetEndpoints(null);

                    // select the best endpoint to use based on the selected URL and the UseSecurity checkbox. 
                    for (int ii = 0; ii < endpoints.Count; ii++)
                    {
                        EndpointDescription endpoint = endpoints[ii];

                        // check for a match on the URL scheme.
                        if (endpoint.EndpointUrl.StartsWith(uri.Scheme))
                        {
                            // check if security was requested.
                            if (!myServer.SecurityPolicy.Equals("None"))
                            {
                                if (endpoint.SecurityMode == MessageSecurityMode.None)
                                {
                                    continue;
                                }
                            }
                            else
                            {
                                if (endpoint.SecurityMode != MessageSecurityMode.None)
                                {
                                    continue;
                                }
                            }

                            // pick the first available endpoint by default.
                            if (endpointDescription == null)
                            {
                                endpointDescription = endpoint;
                            }

                            // The security level is a relative measure assigned by the server to the 
                            // endpoints that it returns. Clients should always pick the highest level
                            // unless they have a reason not too.
                            if (endpoint.SecurityLevel > endpointDescription.SecurityLevel)
                            {
                                endpointDescription = endpoint;
                            }
                        }
                    }

                    // pick the first available endpoint by default.
                    if (endpointDescription == null && endpoints.Count > 0)
                    {
                        endpointDescription = endpoints[0];
                    }
                }

                // if a server is behind a firewall it may return URLs that are not accessible to the client.
                // This problem can be avoided by assuming that the domain in the URL used to call 
                // GetEndpoints can be used to access any of the endpoints. This code makes that conversion.
                // Note that the conversion only makes sense if discovery uses the same protocol as the endpoint.

                Uri endpointUrl = Utils.ParseUri(endpointDescription.EndpointUrl);



                if (endpointUrl != null && endpointUrl.Scheme == uri.Scheme)
                {
                    UriBuilder builder = new UriBuilder(endpointUrl);
                    builder.Host = uri.DnsSafeHost;
                    builder.Port = uri.Port;
                    endpointDescription.EndpointUrl = builder.ToString();
                }
            }
            catch
            {
                endpointDescription = new EndpointDescription();
                endpointDescription.EndpointUrl = myServer.ServerName;

                //ABA 2014-10-10
                if (myServer.SecurityPolicy.Equals("None"))
                {
                    endpointDescription.SecurityPolicyUri = SecurityPolicies.None;
                }
                //Commented by MM 03/07/2019
                //else if (myServer.SecurityPolicy.Equals("Basic128Rsa15"))
                //{
                //    endpointDescription.SecurityPolicyUri = SecurityPolicies.Basic128Rsa15;
                //}
                else if (myServer.SecurityPolicy.Equals("Basic256Sha256"))
                {
                    endpointDescription.SecurityPolicyUri = SecurityPolicies.Basic256Sha256;
                }
                else if (myServer.SecurityPolicy.Equals("Basic256"))
                {
                    endpointDescription.SecurityPolicyUri = SecurityPolicies.Basic256;
                }

                try
                {
                    MessageSecurityMode myMode;
                    myMode = (MessageSecurityMode)Enum.Parse(typeof(MessageSecurityMode), myServer.SecurityMode, false);
                    //endpointDescription.SecurityMode      = MessageSecurityMode.SignAndEncrypt;
                    endpointDescription.SecurityMode = myMode;
                }
                catch
                {
                    endpointDescription.SecurityMode = MessageSecurityMode.None;
                }

                // specify the transport profile.
                if (myServer.Protocol.Equals("opc.tcp"))
                {
                    endpointDescription.TransportProfileUri = Profiles.UaTcpTransport;
                }
                //added OA 2018-04-27
                else if (myServer.Protocol.Equals("http"))
                {
                    //OA-2018-06-18  endpointDescription.TransportProfileUri = Profiles.WsHttpXmlOrBinaryTransport;
                }
                else //added OA 2018-04-27
                {
                    endpointDescription.TransportProfileUri = Profiles.HttpsBinaryTransport; //OA-2018-06-18 HttpsXmlOrBinaryTransport;
                }
                //else  //OA 2018-04-27
                //{
                //    endpointDescription.TransportProfileUri = Profiles.WsHttpXmlOrBinaryTransport;
                //}

                if (myServer.UserIdentity.Equals(UserIdentityType.Certificate))
                {
                    // load the the server certificate from the local certificate store.
                    CertificateIdentifier certificateIdentifier = new CertificateIdentifier();

                    certificateIdentifier.StoreType = CertificateStoreType.X509Store; //OA-2018-06-18 .Windows;

                    if (!String.IsNullOrEmpty(myServer.CertificationStore))
                    {
                        //certificateIdentifier.StorePath = "LocalMachine\\UA Applications";
                        certificateIdentifier.StorePath = myServer.CertificationStore;
                    }
                    else
                    {
                        using (System.IO.FileStream fs = System.IO.File.OpenRead(myServer.CertificationPath))
                        {
                            byte[] bytes = new byte[fs.Length];
                            fs.Read(bytes, 0, Convert.ToInt32(fs.Length));

                            certificateIdentifier.RawData = bytes;
                        }
                    }

                    //certificateIdentifier.SubjectName = "ONBServer";//commented by HHA 12/11//2019

                    //OA-2018-06-25
                    //X509Certificate2 serverCertificate =  certificateIdentifier.Find();
                    X509Certificate2 serverCertificate = certificateIdentifier.Find().Result;

                    if (serverCertificate == null)
                    {
                        throw ServiceResultException.Create(StatusCodes.BadCertificateInvalid, "Could not find server certificate: {0}", certificateIdentifier.SubjectName);
                    }

                    endpointDescription.ServerCertificate = serverCertificate.GetRawCertData();

                }
            }

            return endpointDescription;
        }
    }
}
