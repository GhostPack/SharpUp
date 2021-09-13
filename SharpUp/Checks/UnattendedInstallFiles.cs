using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpUp.Checks
{
    public class UnattendedInstallFiles : VulnerabilityCheck
    {
        private static string _windir = System.Environment.GetEnvironmentVariable("windir");
        private static string[] _searchLocations =
                {
                    String.Format("{0}\\sysprep\\sysprep.xml", _windir),
                    String.Format("{0}\\sysprep\\sysprep.inf", _windir),
                    String.Format("{0}\\sysprep.inf", _windir),
                    String.Format("{0}\\Panther\\Unattended.xml", _windir),
                    String.Format("{0}\\Panther\\Unattend.xml", _windir),
                    String.Format("{0}\\Panther\\Unattend\\Unattend.xml", _windir),
                    String.Format("{0}\\Panther\\Unattend\\Unattended.xml", _windir),
                    String.Format("{0}\\System32\\Sysprep\\unattend.xml", _windir),
                    String.Format("{0}\\System32\\Sysprep\\Panther\\unattend.xml", _windir)
                };
        public UnattendedInstallFiles()
        {
            _name = "Unattended Install Files";

            foreach (string _searchLocation in _searchLocations)
            {
                if (System.IO.File.Exists(_searchLocation))
                {
                    _isVulnerable = true;
                    _details.Add(_searchLocation);
                }
            }
        }
    }
}
