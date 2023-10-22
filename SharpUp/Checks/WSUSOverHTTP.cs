using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SharpUp.Utilities.RegistryUtils;

namespace SharpUp.Checks
{
    public class WSUSOverHTTP : VulnerabilityCheck
    {
        private static string _regPath = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate";
        private static string _regName = "WUServer";
        private static string _regPathEnabled = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU";
        private static string _regNameEnabled = "UseWUServer";

        public WSUSOverHTTP()
        {
            _name = "WSUS updates over HTTP";
            string WSUSOverHTTPHKLM = GetRegValue("HKLM", _regPath, _regName);
            string WSUSEnabledHKLM = GetRegValue("HKLM", _regPathEnabled, _regNameEnabled);

            if (WSUSOverHTTPHKLM.ToLower().StartsWith("http://") & (WSUSEnabledHKLM == "1"))
            {
                _details.Add($"WUServer: {WSUSOverHTTPHKLM}");
                _isVulnerable = true;
            }
        }
    }
}
