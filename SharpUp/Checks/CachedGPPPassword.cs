using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using static SharpUp.Utilities.FileUtils;

namespace SharpUp.Checks
{
    public class CachedGPPPassword : VulnerabilityCheck
    {
        private static string allUsers = System.Environment.GetEnvironmentVariable("ALLUSERSPROFILE");
        public CachedGPPPassword()
        {
            _name = "Cached GPP Password";
            try
            {
                if (!allUsers.Contains("ProgramData"))
                {
                    // Before Windows Vista, the default value of AllUsersProfile was "C:\Documents and Settings\All Users"
                    // And after, "C:\ProgramData"
                    allUsers += "\\Application Data";
                }
                allUsers += "\\Microsoft\\Group Policy\\History"; // look only in the GPO cache folder

                List<String> files = FindFiles(allUsers, "*.xml");

                // files will contain all XML files
                foreach (string file in files)
                {
                    if (!(file.Contains("Groups.xml") || file.Contains("Services.xml")
                        || file.Contains("Scheduledtasks.xml") || file.Contains("DataSources.xml")
                        || file.Contains("Printers.xml") || file.Contains("Drives.xml"))
                        || file.Contains("Registry.xml"))
                    {
                        continue; // uninteresting XML files, move to next
                    }
                    if (ParseGPPPasswordFromXml(file, out GPPPassword result))
                    {
                        _isVulnerable = true;
                        _details.Add(result.ToString());
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
