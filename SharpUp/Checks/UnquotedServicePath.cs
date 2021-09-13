using Microsoft.Win32;
using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SharpUp.Utilities.FileUtils;

namespace SharpUp.Checks
{
    public class UnquotedServicePath : VulnerabilityCheck
    {
        public UnquotedServicePath()
        {
            _name = "Services with Unquoted Paths";

            RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            foreach (string subkey in services.GetSubKeyNames())
            {
                RegistryKey serviceKey = Registry.LocalMachine.OpenSubKey(string.Format(@"SYSTEM\CurrentControlSet\Services\{0}", subkey));
                string path = ((string)serviceKey.GetValue("ImagePath", "")).Trim();
                if (path != "" && 
                    !path.StartsWith("\"") && 
                    !path.StartsWith("'") && 
                    path.Substring(0, path.ToLower().IndexOf(".exe") + 4).Contains(" "))
                {
                    string startType = "Disabled";
                    switch ((int)serviceKey.GetValue("Start", 0))
                    {
                        case 2:
                            startType = "Automatic";
                            break;
                        case 3:
                            startType = "Manual";
                            break;
                        case 4:
                            startType = "Disabled";
                            break;
                        default:
                            startType = "Unknown";
                            break;
                    }
                    List<string> modPaths = new List<string>();
                    string executable_path = path.Substring(0, path.ToLower().IndexOf(".exe") + 4);
                    int num_spaces = executable_path.Split(' ').Length - 1;
                    int lastFound = 0;
                    for (int x = 0; x < num_spaces; ++x)
                    {
                        string new_path = path.Substring(0, path.ToLower().IndexOf(' ', lastFound));
                        lastFound = path.ToLower().IndexOf(' ', lastFound) + 1;
                        string check_path = new_path.Substring(0, new_path.LastIndexOf('\\')) + "\\";
                        if (CheckModifiableAccess(check_path, true))
                        {
                            if (!modPaths.Contains(new_path))
                            {
                                _isVulnerable = true;
                                _details.Add($"Service '{subkey}' (StartMode: {startType}) has executable '{path}', but '{new_path}' is modifable.");
                            }
                        }
                    }
                }

            }
        }
    }
}
