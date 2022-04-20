using SharpUp.Classes;
using System;
using System.IO;
using static SharpUp.Utilities.RegistryUtils;
using System.Diagnostics;
using System.Collections.Generic;
using static SharpUp.Utilities.FileUtils;
using System.Security.Principal;
using static SharpUp.Native.Win32;
using System.Security.AccessControl;

namespace SharpUp.Checks
{
    public class ProcessDLLHijack : VulnerabilityCheck
    {
        private static string _regPath = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDlls";
        
        // For future use
        private static string GetProcessUser(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                string user = wi.Name;
                return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }

        public ProcessDLLHijack()
		      {
            // TODO: Take argements and add them to an array for scoping
            //string[] options = args;

            // Registry key where known DLLs are listed
            string[] keyname = GetRegSubkeys("HKLM", _regPath);

            // Create List for DLL values
            List<string> Dlls = new List<string>();

            // Get the value for each of the values and add it to the list
            foreach (string valuename in keyname)
            {
                string dllname = valuename.ToLower();
                Dlls.Add(dllname);
            }

            // Get all running processes
            Process[] processes = Process.GetProcesses();

            foreach (Process process in processes)
            {
                // Try to check the modules loaded for the process
                try
                {
                    // Go through each module loaded in the process
                    var processmodules = process.Modules;
                    foreach (ProcessModule module in processmodules)
                    {
                        string modules = module.ModuleName;
                        modules = modules.ToLower();
                        string filepath = module.FileName.ToLower();
                        bool writeperms = CheckAccess(filepath, FileSystemRights.Write);
                        // Exclude items that do not end with .dll, exclude known dlls, exclude items in c:\\windows, exclude files that do not have the correct permissions
                        if (module.FileName.EndsWith(".dll") && !Dlls.Contains(modules) && !filepath.Contains("c:\\windows") && writeperms == true)
                        {
                            if (filepath.Contains("c:\\program files"))
                            {
                                Console.WriteLine("[+] Potenatially Hijackable DLL: {0}\n" +
                                    "[!] Files in C:\\Program Files and C:\\Program Files (x86) may be false positives. Permissions should be verified manually.\n" +
                                    "[+] Associated Process is {1} with PID {2}",
                                    module.FileName.ToString(),
                                    process.ProcessName.ToString(),
                                    process.Id.ToString());
                            }
                            else
                            {
                                Console.WriteLine("[+] Hijackable DLL: {0}\n" +
                                    "[+] Associated Process is {1} with PID {2} ",
                                    module.FileName.ToString(),
                                    process.ProcessName.ToString(),
                                    process.Id.ToString());
                            }
                        }
                    }
                }
                catch
                {
                    // Output for when the current user doesn't have permissions for a process
                    // Console.WriteLine("[-] Access denied for {0} under PID {1}", process.ProcessName.ToString(), process.Id.ToString());
                    continue;

                }
            }
        }
    }
}
