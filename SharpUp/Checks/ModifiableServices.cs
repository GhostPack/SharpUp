using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using static SharpUp.Native.Win32;

namespace SharpUp.Checks
{
    public class ModifiableServices : VulnerabilityCheck
    {
        public ModifiableServices()
        {
            _name = "Modifiable Services";
            ServiceController[] scServices;
            scServices = ServiceController.GetServices();

            var GetServiceHandle = typeof(System.ServiceProcess.ServiceController).GetMethod("GetServiceHandle", BindingFlags.Instance | BindingFlags.NonPublic);

            object[] readRights = { 0x00020000 };

            ServiceAccessRights[] ModifyRights =
            {
                ServiceAccessRights.ChangeConfig,
                ServiceAccessRights.WriteDac,
                ServiceAccessRights.WriteOwner,
                ServiceAccessRights.GenericAll,
                ServiceAccessRights.GenericWrite,
                ServiceAccessRights.AllAccess
            };

            foreach (ServiceController sc in scServices)
            {
                try
                {
                    IntPtr handle = (IntPtr)GetServiceHandle.Invoke(sc, readRights);
                    ServiceControllerStatus status = sc.Status;
                    byte[] psd = new byte[0];
                    uint bufSizeNeeded;
                    bool ok = QueryServiceObjectSecurity(handle, SecurityInfos.DiscretionaryAcl, psd, 0, out bufSizeNeeded);

                    if (!ok)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == 122 || err == 0)
                        { // ERROR_INSUFFICIENT_BUFFER
                          // expected; now we know bufsize
                            psd = new byte[bufSizeNeeded];
                            ok = QueryServiceObjectSecurity(handle, SecurityInfos.DiscretionaryAcl, psd, bufSizeNeeded, out bufSizeNeeded);
                        }
                        else
                        {
                            //throw new ApplicationException("error calling QueryServiceObjectSecurity() to get DACL for " + _name + ": error code=" + err);
                            continue;
                        }
                    }
                    if (!ok)
                    {
                        //throw new ApplicationException("error calling QueryServiceObjectSecurity(2) to get DACL for " + _name + ": error code=" + Marshal.GetLastWin32Error());
                        continue;
                    }

                    // get security descriptor via raw into DACL form so ACE ordering checks are done for us.
                    RawSecurityDescriptor rsd = new RawSecurityDescriptor(psd, 0);
                    RawAcl racl = rsd.DiscretionaryAcl;
                    DiscretionaryAcl dacl = new DiscretionaryAcl(false, false, racl);

                    WindowsIdentity identity = WindowsIdentity.GetCurrent();

                    foreach (System.Security.AccessControl.CommonAce ace in dacl)
                    {
                        if ((identity.Groups.Contains(ace.SecurityIdentifier) || ace.SecurityIdentifier == identity.User) &&
                            ace.AceType == AceType.AccessAllowed)
                        {
                            ServiceAccessRights serviceRights = (ServiceAccessRights)ace.AccessMask;
                            foreach (ServiceAccessRights ModifyRight in ModifyRights)
                            {
                                if ((ModifyRight & serviceRights) == ModifyRight)
                                {
                                    ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", String.Format("SELECT * FROM win32_service WHERE Name LIKE '{0}'", sc.ServiceName));
                                    ManagementObjectCollection data = wmiData.Get();

                                    foreach (ManagementObject result in data)
                                    {
                                        _isVulnerable = true;
                                        _details.Add($"Service '{result["Name"]}' (State: {result["State"]}, StartMode: {result["StartMode"]})");
                                    }
                                    break;
                                }
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
}
