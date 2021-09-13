using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using static SharpUp.Utilities.FileUtils;

namespace SharpUp.Checks
{
    public class DomainGPPPassword : VulnerabilityCheck
    {
        private static string DNSDomain = System.Environment.GetEnvironmentVariable("USERDNSDOMAIN");
        public DomainGPPPassword()
        {
            _name = "GPP Password in SYSVOL";
            try
            {
                if (DNSDomain.Length > 1)
                {
                    List<String> files = FindFiles("\\\\" + DNSDomain + "\\SYSVOL", "*.xml");

                    // files will contain 
                    foreach (string file in files)
                    {
                        if (file.Contains("Registry.xml") ||
                            file.Contains("Groups.xml") ||
                            file.Contains("Services.xml") ||
                            file.Contains("ScheduledTasks.xml") ||
                            file.Contains("DataSources.xml") ||
                            file.Contains("Printers.xml") ||
                            file.Contains("Drives.xml"))
                        {
                            if (ParseGPPPasswordFromXml(file, out GPPPassword result))
                            {
                                _isVulnerable = true;
                                _details.Add(result.ToString());
                            }
                        }
                    }

                }
                else
                {
                    _details.Add("Error: Machine is not a domain member or User is not a member of the domain.");
                }



            }
            catch (Exception ex)
            {
                _details.Add(String.Format("[X] Exception: {0}", ex.Message));
            }
        }
    }
}
