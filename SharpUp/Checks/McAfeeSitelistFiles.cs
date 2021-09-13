using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static SharpUp.Utilities.FileUtils;

namespace SharpUp.Checks
{
    public class McAfeeSitelistFiles : VulnerabilityCheck
    {
        private static string _drive = System.Environment.GetEnvironmentVariable("SystemDrive");
        private static string[] _searchLocations =
        {
            String.Format("{0}\\Program Files\\", _drive),
            String.Format("{0}\\Program Files (x86)\\", _drive),
            String.Format("{0}\\Documents and Settings\\", _drive),
            String.Format("{0}\\Users\\", _drive)
        };
        public McAfeeSitelistFiles()
        {
            _name = "McAfee SiteList.xml Files";
            foreach (string SearchLocation in _searchLocations)
            {
                List<string> files = FindFiles(SearchLocation, "SiteList.xml");

                foreach (string file in files)
                {
                    _isVulnerable = true;
                    _details.Add(file);
                }
            }
        }
    }
}
