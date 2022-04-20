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
            foreach (string file in allfiles)
            {
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
                            string triggerlist;

                            // Get task name
                            XmlNodeList task = xmlDocument.GetElementsByTagName("URI");
                            for (int a = 0; a < task.Count; a++)
                            {
                                URIpath = task[a].InnerXml;
                                // Get task triggers
                                XmlNodeList trigger = xmlDocument.GetElementsByTagName("Triggers");
                                for (int b = 0; b < trigger.Count; b++)
                                {
                                    triggerlist = trigger[b].InnerXml;
                                    Console.WriteLine("[+] Modifiable Task {0}.\n" +
                                    "[+] Command executes {1}, which the current user can modify.", URIpath, commandpath
                                    );
                                    string path = commandpath.ToLower();
                                    if(path.Contains("c:\\program files"))
                                    {
                                        Console.WriteLine("[!] Warning: File paths containing Program Files could be false positives. Please check manually to confirm.");
                                    }
                                }
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
