using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SharpUp.Utilities.RegistryUtils;

namespace SharpUp.Checks
{
    public class AlwaysInstallElevated : VulnerabilityCheck
    {
        private static string _regPath = "Software\\Policies\\Microsoft\\Windows\\Installer";
        private static string _regName = "AlwaysInstallElevated";
        
        public AlwaysInstallElevated()
        {
            _name = "Always Install Elevated";
            string AlwaysInstallElevatedHKLM = GetRegValue("HKLM", _regPath, _regName);
            string AlwaysInstallElevatedHKCU = GetRegValue("HKCU", _regPath, _regName);
            if (!string.IsNullOrEmpty(AlwaysInstallElevatedHKCU))
            {
                _details.Add($"HKCU: {AlwaysInstallElevatedHKCU}");
                _isVulnerable = true;
            }
            if (!string.IsNullOrEmpty(AlwaysInstallElevatedHKLM))
            {
                _details.Add($"HKLM: {AlwaysInstallElevatedHKLM}");
                _isVulnerable = true;
            }
        }
    }
}
