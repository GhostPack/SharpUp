using SharpUp.Classes;
using System;
using System.IO;
using System.Xml;
using static SharpUp.Utilities.FileUtils;
using System.Security.AccessControl;

namespace SharpUp.Checks
{
    public class ModifiableScheduledTaskFile : VulnerabilityCheck
    {
        public ModifiableScheduledTaskFile()
        {
            try
            {
                string tasksDir = Environment.GetEnvironmentVariable("SystemRoot");
                tasksDir += IntPtr.Size == 8 ? "\\System32\\Tasks" : "\\SysWOW64\\Tasks";
                string[] allfiles = Directory.GetFiles(tasksDir);

                foreach (string file in allfiles)
                {
                    bool taskPerms = false;
                    bool binPerms = false;
                    // Check if task file is writable
                    taskPerms = CheckAccess(file, FileSystemRights.Write);

                    try
                    {
                        // Load XML document
                        XmlDocument xmlDocument = new XmlDocument();
                        xmlDocument.Load(file);
                        // Get the task name 
                        XmlNodeList task = xmlDocument.GetElementsByTagName("URI");
                        // Get the command (this is what will be executed) 
                        XmlNodeList command = xmlDocument.GetElementsByTagName("Command");
                        for (int i = 0; i < command.Count; i++)
                        {
                            string commandpath = command[i].InnerXml;

                            // Check binary file permissions
                            binPerms = CheckAccess(commandpath, FileSystemRights.Write);
                            if (binPerms || taskPerms)
                            {
                                for (int a = 0; a < task.Count; a++)
                                {
                                    string URIpath = task[a].InnerXml;
                                    URIpath = task[a].InnerXml;
                                    Console.WriteLine("\tTask Name              : {0}", URIpath);
                                    Console.WriteLine("\tTask Path              : {0}", file);
                                    Console.WriteLine("\tCommand                : {0}", commandpath);
                                    Console.WriteLine("\tTask XML Modifiable    : {0}", taskPerms);
                                    Console.WriteLine("\tTask Binary Modifiable : {0}", binPerms);
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
            catch
            {
                Console.WriteLine("[!] Modifialbe scheduled tasks were not evaluated due to permissions.");
            }
        }
    }
}