using Microsoft.Win32;
using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using static SharpUp.Utilities.RegistryUtils;

namespace SharpUp.Checks
{
    public class ModifiableServiceRegistryKeys : VulnerabilityCheck
    {
        public ModifiableServiceRegistryKeys()
        {
            _name = "Services with Modifiable Registry Keys";
            // checks if the current user has rights to modify the given registry

            ServiceController[] scServices;
            scServices = ServiceController.GetServices();

            WindowsIdentity identity = WindowsIdentity.GetCurrent();

            foreach (ServiceController sc in scServices)
            {
                try
                {
                    RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\" + sc.ServiceName);
                    if (IsModifiableKey(key))
                    {
                        ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", String.Format("SELECT * FROM win32_service WHERE Name LIKE '{0}'", sc.ServiceName));
                        ManagementObjectCollection data = wmiData.Get();

                        foreach (ManagementObject result in data)
                        {
                            _isVulnerable = true;
                            _details.Add($"Service '{result["Name"]}' (State: {result["State"]}, " +
                                         $"StartMode: {result["StartMode"]}) : " +
                                         $"{"SYSTEM\\CurrentControlSet\\Services\\" + sc.ServiceName}");
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
}
