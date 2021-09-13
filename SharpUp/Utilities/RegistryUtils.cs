using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace SharpUp.Utilities
{
    public static class RegistryUtils
    {
        public static string GetRegValue(string hive, string path, string value)
        {
            // returns a single registry value under the specified path in the specified hive (HKLM/HKCU)
            string regKeyValue = "";
            if (hive == "HKCU")
            {
                var regKey = Registry.CurrentUser.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
            else if (hive == "HKU")
            {
                var regKey = Registry.Users.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
            else
            {
                var regKey = Registry.LocalMachine.OpenSubKey(path);
                if (regKey != null)
                {
                    regKeyValue = String.Format("{0}", regKey.GetValue(value));
                }
                return regKeyValue;
            }
        }

        public static Dictionary<string, object> GetRegValues(string hive, string path)
        {
            // returns all registry values under the specified path in the specified hive (HKLM/HKCU)
            Dictionary<string, object> keyValuePairs = null;

            if (hive == "HKCU")
            {
                using (var regKeyValues = Registry.CurrentUser.OpenSubKey(path))
                {
                    if (regKeyValues != null)
                    {
                        var valueNames = regKeyValues.GetValueNames();
                        keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                    }
                }
            }
            else if (hive == "HKU")
            {
                using (var regKeyValues = Registry.Users.OpenSubKey(path))
                {
                    if (regKeyValues != null)
                    {
                        var valueNames = regKeyValues.GetValueNames();
                        keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                    }
                }
            }
            else
            {
                using (var regKeyValues = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (regKeyValues != null)
                    {
                        var valueNames = regKeyValues.GetValueNames();
                        keyValuePairs = valueNames.ToDictionary(name => name, regKeyValues.GetValue);
                    }
                }
            }
            return keyValuePairs;
        }

        public static string[] GetRegSubkeys(string hive, string path)
        {
            // returns an array of the subkeys names under the specified path in the specified hive (HKLM/HKCU/HKU)
            try
            {
                Microsoft.Win32.RegistryKey myKey = null;
                if (hive == "HKLM")
                {
                    myKey = Registry.LocalMachine.OpenSubKey(path);
                }
                else if (hive == "HKU")
                {
                    myKey = Registry.Users.OpenSubKey(path);
                }
                else
                {
                    myKey = Registry.CurrentUser.OpenSubKey(path);
                }
                String[] subkeyNames = myKey.GetSubKeyNames();
                return myKey.GetSubKeyNames();
            }
            catch
            {
                return new string[0];
            }
        }

        public static bool IsModifiableKey(RegistryKey key)
        {
            RegistryRights[] ModifyRights =
            {
                RegistryRights.ChangePermissions,
                RegistryRights.FullControl,
                RegistryRights.TakeOwnership,
                RegistryRights.SetValue,
                RegistryRights.WriteKey
            };
            WindowsIdentity identity = WindowsIdentity.GetCurrent();

            AuthorizationRuleCollection rules = key.GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));

            foreach (RegistryAccessRule rule in rules)
            {
                if (identity.Groups.Contains(rule.IdentityReference) || rule.IdentityReference == identity.User)
                {
                    foreach (RegistryRights AccessRight in ModifyRights)
                    {
                        if ((AccessRight & rule.RegistryRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                            {
                                return true;
                            }

                        }
                    }
                }
            }
            return false;
        }

    }
}
