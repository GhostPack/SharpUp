using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace SharpUp.Utilities
{
    public static class FileUtils
    {
        public static bool CheckAccess(string Path, FileSystemRights AccessRight)
        {
            // checks if the current user has the specified AccessRight to the specified file or folder
            // from https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345

            if (string.IsNullOrEmpty(Path)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(Path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
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

        public static bool CheckModifiableAccess(string Path)
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
                        if (identity.Groups.Contains(rule.IdentityReference))
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
