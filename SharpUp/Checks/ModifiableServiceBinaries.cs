using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using static SharpUp.Utilities.FileUtils;

namespace SharpUp.Checks
{
    public class ModifiableServiceBinaries : VulnerabilityCheck
    {
        public ModifiableServiceBinaries()
        {
            _name = "Modifiable Service Binaries";
            try
            {
                // finds any service binaries that the current can modify
                //      TODO: or modify the parent folder

                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service");
                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    if (result["PathName"] != null)
                    {
                        Match path = Regex.Match(result["PathName"].ToString(), @"^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*", RegexOptions.IgnoreCase);
                        String binaryPath = path.Groups[1].ToString();

                        if (CheckModifiableAccess(binaryPath))
                        {
                            _isVulnerable = true;
                            _details.Add($"Service '{result["Name"]}' (State: {result["State"]}, StartMode: {result["StartMode"]}) : {result["PathName"]}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _details.Add($"[X] Exception: {ex.Message}");
            }
        }
    }
}
