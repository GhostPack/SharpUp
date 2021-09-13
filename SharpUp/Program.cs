using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using static SharpUp.Utilities.IdentityUtils;

namespace SharpUp
{
    class Program
    {
        static bool auditMode = false;
        public static void PrivescChecks(Type[] checks)
        {
            bool isHighIntegrity = IsHighIntegrity();
            bool isLocalAdmin = IsLocalAdmin();
            bool shouldQuit = false;

            if (isHighIntegrity)
            {
                Console.WriteLine("\r\n[*] Already in high integrity, no need to privesc!");
                shouldQuit = true;
            }
            else if (!isHighIntegrity && isLocalAdmin)
            {
                Console.WriteLine("\r\n[*] In medium integrity but user is a local administrator- UAC can be bypassed.");
                shouldQuit = true;
            }

            // if already admin we can quit without running all checks
            if (shouldQuit)
            {
                if (!auditMode)
                {
                    Console.WriteLine("\r\n[*] Quitting now, re-run with \"audit\" argument to run checks anyway (audit mode).");
                    return;
                }
                else
                {
                    // except if auditMode has explictly been asked
                    Console.WriteLine($"\r\n[*] Audit mode: running an additional {checks.Length} check(s).");
                    if (isHighIntegrity)
                    {
                        Console.WriteLine("[*] Note: Running audit mode in high integrity will yield a large number of false positives.");
                    }
                }
            }
            
            List<VulnerabilityCheck> vulnerableChecks = new List<VulnerabilityCheck>();
            Mutex mtx = new Mutex();
            List<Thread> runningThreads = new List<Thread>();
            foreach(Type t in checks)
            {
                Thread vulnThread = new Thread(() =>
                {
                    try
                    {
                        VulnerabilityCheck c = (VulnerabilityCheck)Activator.CreateInstance(t);
                        if (c.IsVulnerable())
                        {
                            mtx.WaitOne();
                            vulnerableChecks.Add(c);
                            mtx.ReleaseMutex();
                        }
                    } catch (Exception ex)
                    {
                        Console.WriteLine("[X] Unhandled exception in {0}: {1}", t.Name, ex.Message);
                    }
                });
                vulnThread.Start();
                runningThreads.Add(vulnThread);
            }
            foreach(Thread t in runningThreads)
            {
                t.Join();
            }

            if (vulnerableChecks.Count == 0)
            {
                Console.WriteLine($"\r\n[-] Not vulnerable to any of the {checks.Length} checked modules.");
            } else
            {
                foreach(VulnerabilityCheck c in vulnerableChecks)
                {
                    Console.WriteLine($"\r\n=== {c.Name()} ===");
                    foreach(string s in c.Details())
                    {
                        Console.WriteLine($"\t{s}");
                    }
                    Console.WriteLine();
                }
            }
        }

        static Type[] GetAvailableChecks()
        {
            return Assembly.GetExecutingAssembly().GetTypes()
                      .Where(t => t.Namespace == "SharpUp.Checks")
                      .ToArray();
        }

        static Type[] GetChecksFromArgumentString(string[] args)
        {
            Type[] allChecks = GetAvailableChecks();
            List<Type> checks = new List<Type>();
            if (args.Contains("audit"))
            {
                auditMode = true;
                if (args.Length == 1)
                {
                    return allChecks;
                }
            }

            foreach(string arg in args)
            {
                foreach(Type t in allChecks)
                {
                    if (t.Name.ToLower() == arg.ToLower())
                    {
                        checks.Add(t);
                    }
                }
            }
            return checks.ToArray();
        }
        static void Usage()
        {
            Type[] checks = GetAvailableChecks();
            string[] checkNames = checks.Select(check => check.Name + "\n").ToArray();

            string strCheck = string.Join("              - ", checkNames);
            string usageString = @"
SharpUp.exe [audit] [check1] [check2]...

    audit   - Specifies whether or not to enable audit mode. If enabled, SharpUp will run vulenrability checks
              regardless if the process is in high integrity or the user is in the local administrator's group.
              If no checks are specified, audit will run all checks. Otherwise, each check following audit will
              be ran.

    check*  - The individual vulnerability check to be ran. Must be one of the following:

              - {0}
            

    Examples:
        SharpUp.exe audit
            -> Runs all vulnerability checks regardless of integrity level or group membership.
        
        SharpUp.exe HijackablePaths
            -> Check only if there are modifiable paths in the user's %PATH% variable.

        SharpUp.exe audit HijackablePaths
            -> Check only for modifiable paths in the user's %PATH% regardless of integrity level or group membership. 
";
            Console.WriteLine(string.Format(usageString, strCheck));
        }

        static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
            {
                Usage();
                return;
            }
            Type[] checks = GetChecksFromArgumentString(args);

            var watch = System.Diagnostics.Stopwatch.StartNew();

            Console.WriteLine("\r\n=== SharpUp: Running Privilege Escalation Checks ===");

            PrivescChecks(checks);

            watch.Stop();
            Console.WriteLine(String.Format("\r\n\r\n[*] Completed Privesc Checks in {0} seconds\r\n", watch.ElapsedMilliseconds / 1000));
        }
    }
}

