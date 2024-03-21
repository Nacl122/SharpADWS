using SharpADWS.ADWS;
using SharpADWS.ADWS.Enumeration;
using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Security.Policy;
using SharpADWS.ADWS.Transfer;
using System.Data.SqlTypes;
using static System.Net.Mime.MediaTypeNames;

namespace SharpADWS.Methods.DNS
{
    internal class Dns
    {
        private ADWSConnection adwsConnection = null;
        private string DefaultNamingContext = null;
        private string DNSRoot = null;
        private string DomainName = null;

        public Dns(ADWSConnection adwsConnection)
        {
            this.adwsConnection = adwsConnection;
            this.DefaultNamingContext = adwsConnection.DefaultNamingContext;
            this.DNSRoot = adwsConnection.DNSRoot;
            this.DomainName = adwsConnection.DomainName;
        }
        public void Query(string name)
        {
            try
            {
                EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
                List<ADObject> dnsObjects = enumerateRequest.Enumerate($"(&(objectClass=dnsNode)(name={name}))", this.DNSRoot, "subtree", new string[] { "name", "dnsRecord", "dNSTombstoned" });
                DNS_RECORD record = dnsObjects[0].DnsRecord;
                Console.WriteLine($"Record: {name}");
                Console.WriteLine($"Type: {record.Type} (A)");
                Console.WriteLine($"Address: {record.GetIPv4Address()}");
            }
            catch {
                Console.WriteLine($"Record: {name}");
                Console.WriteLine("Status: Record not found or insufficient user permissions");
            }
        }

        public void Query_all()
        {
            List<string> names = Get_All_Computers();
            foreach (string name in names)
            {
                try
                {
                    EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
                    List<ADObject> dnsObjects = enumerateRequest.Enumerate($"(&(objectClass=dnsNode)(name={name}))", this.DNSRoot, "subtree", new string[] { "name", "dnsRecord", "dNSTombstoned" });
                    DNS_RECORD record = dnsObjects[0].DnsRecord;
                    Console.WriteLine($"Record: {name}");
                    Console.WriteLine($"Type: {record.Type} (A)");
                    Console.WriteLine($"Address: {record.GetIPv4Address()}");
                }
                catch
                {
                    Console.WriteLine($"Record: {name}");
                    Console.WriteLine("Status: Record not found or insufficient user permissions");
                }
                Console.WriteLine();
            }
          
        }
        public List<string> Get_All_Computers() {
            EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
            List<ADObject> computerObjects = enumerateRequest.Enumerate($"(&(operatingSystem=*)(name=*))", this.DefaultNamingContext, "subtree", new string[] { "name", "dnsRecord", "dNSTombstoned" });
            List<string> names = new List<string>();
            foreach (ADObject computerObject in computerObjects)
            {
                names.Add(computerObject.Name);
            }
            return names;
        }
        
        public void modify(string name, string data)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
            List<ADObject> dnsObjects = enumerateRequest.Enumerate($"(&(objectClass=dnsNode)(name={name}))", this.DNSRoot, "subtree", new string[] { "name", "dnsRecord", "dNSTombstoned", "DistinguishedName" });
            DNS_RECORD dnsrecord = dnsObjects[0].DnsRecord;
            IPAddress ipAddress;
            byte[] ipAddressBytes;
            if (IPAddress.TryParse(data, out ipAddress))
            {
                ipAddressBytes = ipAddress.GetAddressBytes();
            }
            else
            {
                throw new InvalidOperationException("Invalid IP address: " + data);
            }
            dnsrecord.Data = ipAddressBytes;
            PutRequest putRequest = new PutRequest(adwsConnection);
            Message modifyResponse = putRequest.ModifyRequest(dnsObjects[0].DistinguishedName, DirectoryAttributeOperation.Replace, "dnsRecord", dnsrecord.ToArray());
            if (!modifyResponse.IsFault)
            {
                Console.WriteLine($"Record: {name}.{this.DomainName}");
                Console.WriteLine($"IP: {data}");
                Console.WriteLine("LDAP operation completed successfully");
            }
            else
            {
                Console.WriteLine($"LDAP operation failed. Message returned from server: {Parse_Error(modifyResponse)}");
            }
        }

        //add A record
        public void Add(string name,string data)
        {
            
            EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
            List<ADObject> dnsObjects = enumerateRequest.Enumerate($"(&(objectClass=dnsNode)(name={name}))", this.DNSRoot, "subtree", new string[] { "name", "dnsRecord", "dNSTombstoned" });
            if (dnsObjects.Count != 0)
            {
                Console.WriteLine("There's already a value on this record");
            }
            else
            { 
                DirectoryAttribute[] directoryAttribute = new DirectoryAttribute[4];
                directoryAttribute[0] = new DirectoryAttribute();
                directoryAttribute[0].Name = "objectClass";
                directoryAttribute[0].Add($"dnsNode");

                directoryAttribute[1] = new DirectoryAttribute();
                directoryAttribute[1].Name = "objectCategory";
                directoryAttribute[1].Add($"CN=Dns-Node,CN=Schema,CN=Configuration,{this.DefaultNamingContext}");

                directoryAttribute[2] = new DirectoryAttribute();
                directoryAttribute[2].Name = "name";
                directoryAttribute[2].Add(name);

                directoryAttribute[3] = new DirectoryAttribute();
                directoryAttribute[3].Name = "dnsRecord";
                directoryAttribute[3].Add(Generate_dnsRecord(data).ToArray());

                CreateRequest createRequest = new CreateRequest(adwsConnection);
                Message addResponse = createRequest.AddRequest($"DC={this.DomainName},{this.DNSRoot}", $"DC={name}", directoryAttribute);
                if (!addResponse.IsFault)
                {
                    Console.WriteLine($"Record: {name}.{this.DomainName}");
                    Console.WriteLine($"IP: {data}");
                    Console.WriteLine("LDAP operation completed successfully");
                }
                else
                {
                    Console.WriteLine(1);
                    Console.WriteLine($"LDAP operation failed. Message returned from server: {Parse_Error(addResponse)}");
                }
            }

        }
        public void ldapremove(string name)
        {
            EnumerateRequest enumerateRequest = new EnumerateRequest(adwsConnection);
            List<ADObject> dnsObjects = enumerateRequest.Enumerate($"(&(objectClass=dnsNode)(name={name}))", this.DNSRoot, "subtree", new string[] { "name", "dnsRecord", "DistinguishedName" });
            if (dnsObjects.Count != 0)
            {
                ADWS.Transfer.DeleteRequest deleteRequest = new ADWS.Transfer.DeleteRequest(adwsConnection);
                Message deletemessage =  deleteRequest.DeleteRequestMessage(dnsObjects[0].DistinguishedName);
                if (!deletemessage.IsFault)
                {
                    Console.WriteLine($"{name}.{this.DomainName} record was deleted");
                }
                else
                {
                    Console.WriteLine($"LDAP operation failed. Message returned from server: {Parse_Error(deletemessage)}");
                }
            }
            else
            {
                Console.WriteLine("Target record not found!");
            }
        }

        public string Parse_Error(Message mess)
        {
            XDocument xmlDoc = XDocument.Parse(mess.ToString());
            XNamespace ns = "http://schemas.microsoft.com/2008/1/ActiveDirectory";
            XElement directoryErrorElement = xmlDoc.Descendants(ns + "DirectoryError").FirstOrDefault();
            XElement messageElement = directoryErrorElement.Element(ns + "Message");
            string message = "";
            if (messageElement != null)
            {
                message = messageElement.Value;
            }
            else
            {
                message = "null";
            }
            return message;
        }

        public DNS_RECORD Generate_dnsRecord(string data)
        {
            ushort Type = 1;

            DNS_RECORD dnsRecord = new DNS_RECORD();
            dnsRecord.Rank = 240;
            dnsRecord.Type = Type;
            dnsRecord.Serial = 196;
            dnsRecord.TtlSeconds = 180;
            dnsRecord.Version = 5;
            IPAddress ipAddress;
            byte[] ipAddressBytes;
            if (IPAddress.TryParse(data, out ipAddress))
            {
                ipAddressBytes = ipAddress.GetAddressBytes();
            }
            else
            {
                throw new InvalidOperationException("Invalid IP address: " + data);
            }
            dnsRecord.Data = ipAddressBytes;
            dnsRecord.DataLength = (ushort)ipAddressBytes.Length;
            return dnsRecord ;
        }
    }
}
