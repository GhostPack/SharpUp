using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Xml;

namespace SharpUp.Utilities
{
    public static class FileUtils
    {
        public struct GPPPassword
        {
            public string UserName;
            public string NewName;
            public string cPassword;
            public string Changed;

            public override string ToString()
            {
                string _uname = UserName;
                string _newname = NewName;
                string _cp = cPassword;
                string _changed = Changed;
                if (string.IsNullOrEmpty(_uname))
                    _uname = "[BLANK]";
                if (string.IsNullOrEmpty(_newname))
                    _newname = "[BLANK]";
                if (string.IsNullOrEmpty(_cp))
                    _cp = "[BLANK]";
                else
                {
                    // will fail on certain XML files like Registry.xml
                    try
                    {
                        _cp = DecryptGPPPassword(_cp);
                    } catch { }
                }
                if (string.IsNullOrEmpty(_changed))
                    _changed = "[BLANK]";
                return $"UserName: {_uname} | NewName: {_newname} | cPassword: {_cp} | Changed: {_changed}";
            }
        }

        public static bool ParseGPPPasswordFromXml(string filePath, out GPPPassword result)
        {
            result = new GPPPassword();
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(filePath);
            if (!xmlDoc.InnerXml.Contains("cpassword"))
            {
                return false; // no "cpassword" => no interesting content, move to next
            }
            if (filePath.Contains("Groups.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/Groups/User/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/Groups/User");
                foreach (XmlAttribute attr in a.Attributes)
                {
                    if (attr.Name.Equals("cpassword"))
                    {
                        result.cPassword = attr.Value;
                    }
                    if (attr.Name.Equals("userName"))
                    {
                        result.UserName = attr.Value;
                    }
                    if (attr.Name.Equals("newName"))
                    {
                        result.NewName = attr.Value;
                    }
                }
                foreach (XmlAttribute attr in b.Attributes)
                {
                    if (attr.Name.Equals("changed"))
                    {
                        result.Changed = attr.Value;
                    }
                }
                //Console.WriteLine("\r\nA{0}", a.Attributes[0].Value);
            }
            else if (filePath.Contains("Services.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/NTServices/NTService/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/NTServices/NTService");
                foreach (XmlAttribute attr in a.Attributes)
                {
                    if (attr.Name.Equals("cpassword"))
                    {
                        result.cPassword = attr.Value;
                    }
                    if (attr.Name.Equals("accountName"))
                    {
                        result.UserName = attr.Value;
                    }
                }
                foreach (XmlAttribute attr in b.Attributes)
                {
                    if (attr.Name.Equals("changed"))
                    {
                        result.Changed = attr.Value;
                    }
                }

            }
            else if (filePath.Contains("Registry.xml"))
            {
                XmlNodeList a = xmlDoc.GetElementsByTagName("Properties");

                foreach (XmlNode b in a)
                {
                    if (b.Name.Equals("DefaultPassword"))
                    {
                        result.cPassword += "," + b.Value;
                    }
                    if (b.Name.Equals("DefaultUsername"))
                    {
                        result.UserName += "," + b.Value;
                    }
                }
            }
            else if (filePath.Contains("Scheduledtasks.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/ScheduledTasks/Task/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/ScheduledTasks/Task");
                foreach (XmlAttribute attr in a.Attributes)
                {
                    if (attr.Name.Equals("cpassword"))
                    {
                        result.cPassword = attr.Value;
                    }
                    if (attr.Name.Equals("runAs"))
                    {
                        result.UserName = attr.Value;
                    }
                }
                foreach (XmlAttribute attr in b.Attributes)
                {
                    if (attr.Name.Equals("changed"))
                    {
                        result.Changed = attr.Value;
                    }
                }

            }
            else if (filePath.Contains("DataSources.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/DataSources/DataSource/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/DataSources/DataSource");
                foreach (XmlAttribute attr in a.Attributes)
                {
                    if (attr.Name.Equals("cpassword"))
                    {
                        result.cPassword = attr.Value;
                    }
                    if (attr.Name.Equals("username"))
                    {
                        result.UserName = attr.Value;
                    }
                }
                foreach (XmlAttribute attr in b.Attributes)
                {
                    if (attr.Name.Equals("changed"))
                    {
                        result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("Printers.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/Printers/SharedPrinter/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/Printers/SharedPrinter");
                foreach (XmlAttribute attr in a.Attributes)
                {
                    if (attr.Name.Equals("cpassword"))
                    {
                        result.cPassword = attr.Value;
                    }
                    if (attr.Name.Equals("username"))
                    {
                        result.UserName = attr.Value;
                    }
                }
                foreach (XmlAttribute attr in b.Attributes)
                {
                    if (attr.Name.Equals("changed"))
                    {
                        result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("Drives.xml"))
            {
                // Drives.xml
                XmlNode a = xmlDoc.SelectSingleNode("/Drives/Drive/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/Drives/Drive");
                foreach (XmlAttribute attr in a.Attributes)
                {
                    if (attr.Name.Equals("cpassword"))
                    {
                        result.cPassword = attr.Value;
                    }
                    if (attr.Name.Equals("username"))
                    {
                        result.UserName = attr.Value;
                    }
                }
                foreach (XmlAttribute attr in b.Attributes)
                {
                    if (attr.Name.Equals("changed"))
                    {
                        result.Changed = attr.Value;
                    }
                }
            } else
            {
                throw new Exception("Unexpected code path.");
            }
            return true;
        }

        public static string DecryptGPPPassword(string cpassword)
        {
            int mod = cpassword.Length % 4;

            switch (mod)
            {
                case 1:
                    cpassword = cpassword.Substring(0, cpassword.Length - 1);
                    break;
                case 2:
                    cpassword += "".PadLeft(4 - mod, '=');
                    break;
                case 3:
                    cpassword += "".PadLeft(4 - mod, '=');
                    break;
                default:
                    break;
            }

            byte[] base64decoded = Convert.FromBase64String(cpassword);

            AesCryptoServiceProvider aesObject = new AesCryptoServiceProvider();

            byte[] aesKey = { 0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b };
            byte[] aesIV = new byte[aesObject.IV.Length];

            aesObject.IV = aesIV;
            aesObject.Key = aesKey;

            ICryptoTransform aesDecryptor = aesObject.CreateDecryptor();
            byte[] outBlock = aesDecryptor.TransformFinalBlock(base64decoded, 0, base64decoded.Length);

            return System.Text.UnicodeEncoding.Unicode.GetString(outBlock);
        }

        public static bool CheckAccess(string Path, FileSystemRights AccessRight)
        {
            // checks if the current user has the specified AccessRight to the specified file or folder
            // from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

            if (string.IsNullOrEmpty(Path)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(Path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                foreach (FileSystemAccessRule rule in rules)
                {

                    var ruleNtAccount = rule.IdentityReference.Translate(typeof(NTAccount));
                    if (identity.Groups.Contains(rule.IdentityReference) ||
                        principal.IsInRole(ruleNtAccount.Value) ||
                        ruleNtAccount.Value == identity.Name)
                    {
                        if ((AccessRight & rule.FileSystemRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }

        public static List<string> FindFiles(string path, string patterns)
        {
            // finds files matching one or more patterns under a given path, recursive
            // adapted from http://csharphelper.com/blog/2015/06/find-files-that-match-multiple-patterns-in-c/
            //      pattern: "*pass*;*.png;"

            var files = new List<string>();

            try
            {
                // search every pattern in this directory's files
                foreach (string pattern in patterns.Split(';'))
                {
                    files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));
                }

                // go recurse in all sub-directories
                foreach (var directory in Directory.GetDirectories(path))
                    files.AddRange(FindFiles(directory, patterns));
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }

            return files;
        }

        public static bool CheckModifiableAccess(string Path, bool FileRightsOnly = false)
        {
            // checks if the current user has rights to modify the given file/directory
            // adapted from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

            if (string.IsNullOrEmpty(Path)) return false;
            // TODO: check if file exists, check file's parent folder

            // rights that signify modiable access
            FileSystemRights[] ModifyRights =
            {
                FileSystemRights.ChangePermissions,
                FileSystemRights.FullControl,
                FileSystemRights.Modify,
                FileSystemRights.TakeOwnership,
                FileSystemRights.Write,
                FileSystemRights.WriteData,
                FileSystemRights.CreateDirectories,
                FileSystemRights.CreateFiles
            };

            if (FileRightsOnly)
            {
                FileSystemRights[] ModifyRightsOnlyFiles =
                {
                    FileSystemRights.FullControl,
                    FileSystemRights.Modify,
                    FileSystemRights.TakeOwnership,
                    FileSystemRights.Write,
                    FileSystemRights.WriteData,
                    FileSystemRights.CreateFiles
                };
                ModifyRights = ModifyRightsOnlyFiles;
            }

            ArrayList paths = new ArrayList();
            paths.Add(Path);

            try
            {
                FileAttributes attr = System.IO.File.GetAttributes(Path);
                if ((attr & FileAttributes.Directory) != FileAttributes.Directory)
                {
                    string parentFolder = System.IO.Path.GetDirectoryName(Path);
                    paths.Add(parentFolder);
                }
            }
            catch
            {
                return false;
            }


            try
            {
                foreach (string candidatePath in paths)
                {
                    AuthorizationRuleCollection rules = Directory.GetAccessControl(candidatePath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                    WindowsIdentity identity = WindowsIdentity.GetCurrent();

                    foreach (FileSystemAccessRule rule in rules)
                    {
                        if (identity.Groups.Contains(rule.IdentityReference) ||
                            rule.IdentityReference == identity.User)
                        {
                            foreach (FileSystemRights AccessRight in ModifyRights)
                            {
                                if ((AccessRight & rule.FileSystemRights) == AccessRight)
                                {
                                    if (rule.AccessControlType == AccessControlType.Allow)
                                        return true;
                                }
                            }
                        }
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
