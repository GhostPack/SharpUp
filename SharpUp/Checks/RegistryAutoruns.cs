using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using static SharpUp.Utilities.FileUtils;
using static SharpUp.Utilities.RegistryUtils;

namespace SharpUp.Checks
{
    public class RegistryAutoruns : VulnerabilityCheck
    {
        private static string[] _autorunLocations = new string[] {
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
                "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
            };

        public RegistryAutoruns()
        {
            _name = "Modifiable Registry AutoRun Files";
            foreach (string autorunLocation in _autorunLocations)
            {
                Dictionary<string, object> settings = GetRegValues("HKLM", autorunLocation);
                if ((settings != null) && (settings.Count != 0))
                {
                    foreach (KeyValuePair<string, object> kvp in settings)
                    {
                        Match path = Regex.Match(kvp.Value.ToString(), @"^\W*([a-z]:\\.+?(\.exe|\.bat|\.ps1|\.vbs))\W*", RegexOptions.IgnoreCase);
                        String binaryPath = path.Groups[1].ToString();

                        if (CheckModifiableAccess(binaryPath))
                        {
                            _isVulnerable = true;
                            _details.Add($"HKLM:\\{autorunLocation} : {binaryPath}");
                        }
                    }
                }
            }
        }
    }
}
