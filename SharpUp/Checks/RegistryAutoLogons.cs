using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SharpUp.Utilities.RegistryUtils;

namespace SharpUp.Checks
{
    public class RegistryAutoLogons : VulnerabilityCheck
    {
        private static string _regWinlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        public RegistryAutoLogons()
        {
            _name = "Registry AutoLogons";
            try
            {

                string AutoAdminLogon = GetRegValue("HKLM", _regWinlogon, "AutoAdminLogon");

                if (AutoAdminLogon.Equals("1"))
                {
                    Console.WriteLine("Registry AutoLogon Found\r\n");
                    string DefaultDomainName = GetRegValue("HKLM", _regWinlogon, "DefaultDomainName");
                    string DefaultUserName = GetRegValue("HKLM", _regWinlogon, "DefaultUserName");
                    string DefaultPassword = GetRegValue("HKLM", _regWinlogon, "DefaultPassword");
                    string AltDefaultDomainName = GetRegValue("HKLM", _regWinlogon, "AltDefaultDomainName");
                    string AltDefaultUserName = GetRegValue("HKLM", _regWinlogon, "AltDefaultUserName");
                    string AltDefaultPassword = GetRegValue("HKLM", _regWinlogon, "AltDefaultPassword");

                    if (!DefaultUserName.Equals("") || !AltDefaultUserName.Equals(""))
                    {
                        _isVulnerable = true;

                        _details.Add(string.Format("DefaultDomainName: {0}", DefaultDomainName));
                        _details.Add(string.Format("DefaultUserName: {0}", DefaultUserName));
                        _details.Add(string.Format("DefaultPassword: {0}", DefaultPassword));
                        _details.Add(string.Format("AltDefaultDomainName: {0}", AltDefaultDomainName));
                        _details.Add(string.Format("AltDefaultUserName: {0}", AltDefaultUserName));
                        _details.Add(string.Format("AltDefaultPassword: {0}", AltDefaultPassword));
                    }
                }

            }
            catch (Exception ex)
            {
                _details.Add(String.Format("[X] Exception: {0}", ex.Message));
            }
        }
    }
}
