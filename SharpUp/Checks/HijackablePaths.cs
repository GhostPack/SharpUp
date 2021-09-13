using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SharpUp.Utilities.RegistryUtils;
using static SharpUp.Utilities.FileUtils;

namespace SharpUp.Checks
{
    public class HijackablePaths : VulnerabilityCheck
    {
        private static string _regPath = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        private static string _regName = "Path";
        public HijackablePaths()
        {
            _name = "Modifiable Folders in %PATH%";
            string path = GetRegValue("HKLM", _regPath, _regName);
            if (string.IsNullOrEmpty(path))
            {
                _isVulnerable = false;
                return;
            }
            string[] pathFolders = path.Split(';');
            foreach (string folder in pathFolders)
            {
                if (CheckModifiableAccess(folder))
                {
                    _isVulnerable = true;
                    _details.Add(folder);
                }
            }
        }
    }
}
