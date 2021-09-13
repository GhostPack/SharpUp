using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using static SharpUp.Native.Win32;

namespace SharpUp.Utilities
{
    public static class IdentityUtils
    {
        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool IsLocalAdmin()
        {
            // checks if the "S-1-5-32-544" in the current token groups set, meaning the user is a local administrator
            string[] SIDs = GetTokenGroupSIDs();

            foreach (string SID in SIDs)
            {
                if (SID == "S-1-5-32-544")
                {
                    return true;
                }
            }
            return false;
        }

        public static string[] GetTokenGroupSIDs()
        {
            // Returns all SIDs that the current user is a part of, whether they are disabled or not.

            // adapted almost directly from https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418

            int TokenInfLength = 0;

            // first call gets length of TokenInformation
            bool Result = GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            Result = GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenGroups, TokenInformation, TokenInfLength, out TokenInfLength);

            if (!Result)
            {
                Marshal.FreeHGlobal(TokenInformation);
                return null;
            }

            TOKEN_GROUPS groups = (TOKEN_GROUPS)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_GROUPS));
            string[] userSIDS = new string[groups.GroupCount];
            int sidAndAttrSize = Marshal.SizeOf(new SID_AND_ATTRIBUTES());
            for (int i = 0; i < groups.GroupCount; i++)
            {
                SID_AND_ATTRIBUTES sidAndAttributes = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    new IntPtr(TokenInformation.ToInt64() + i * sidAndAttrSize + IntPtr.Size), typeof(SID_AND_ATTRIBUTES));

                IntPtr pstr = IntPtr.Zero;
                ConvertSidToStringSid(sidAndAttributes.Sid, out pstr);
                userSIDS[i] = Marshal.PtrToStringAuto(pstr);
                LocalFree(pstr);
            }

            Marshal.FreeHGlobal(TokenInformation);
            return userSIDS;
        }
    }
}
