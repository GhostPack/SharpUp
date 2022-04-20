using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using static SharpUp.Utilities.FileUtils;
using System.Security.Principal;
using static SharpUp.Native.Win32;
using System.Security.AccessControl;

namespace SharpUp.Checks
{
    public class ModifiableScheduledTaskFile : VulnerabilityCheck
    {
        public ModifiableScheduledTaskFile()
        {
            string varName = Environment.GetEnvironmentVariable("SystemRoot");
            varName += IntPtr.Size == 8 ? "\\System32\\Tasks" : "\\SysWOW64\\Tasks";
            string[] allfiles = Directory.GetFiles(varName);

            // Warning for Program Files
            Console.WriteLine("[!] Warning: File paths containing Program Files could be false positives. Please check manually to confirm.");
            
            foreach (string file in allfiles)
            {
                // Check if task file is writable
                bool taskperms = CheckAccess(file, FileSystemRights.Write);
                if(taskperms == false)
                {
                    Console.WriteLine("[+] The current user has write permissions to {0}", file);
                    Console.WriteLine();
                }
                try
                {
                    // Load XML document
                    XmlDocument xmlDocument = new XmlDocument();
                    xmlDocument.Load(file);

                    // Get the command (this is what will be executed) 
                    XmlNodeList command = xmlDocument.GetElementsByTagName("Command");
                    for (int i = 0; i < command.Count; i++)
                    {
                        string commandpath = command[i].InnerXml;

                        // Check file permissions
                        bool writeperms = CheckAccess(commandpath, FileSystemRights.Write);
                        if(writeperms == false)
                        {
                            string URIpath;
                            // Get task name
                            XmlNodeList task = xmlDocument.GetElementsByTagName("URI");
                            for (int a = 0; a < task.Count; a++)
                            {
                                URIpath = task[a].InnerXml;
                                Console.WriteLine("[+] Modifiable Task {0}", URIpath);
                                Console.WriteLine("[+] Command executes {0}", commandpath);
                                Console.WriteLine("\tReason : User can modify command binary.");
                                Console.WriteLine();
                            }
                        }
                    }
                }
                catch
                {
                    continue;
                }
            }
        }
    }
}
