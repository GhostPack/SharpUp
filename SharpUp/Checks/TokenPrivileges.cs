using SharpUp.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using static SharpUp.Native.Win32;

namespace SharpUp.Checks
{
    public class TokenPrivileges : VulnerabilityCheck
    {
        private static string[] _specialPrivileges = {
                "SeSecurityPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
                "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
                "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege"
            };
        public TokenPrivileges()
        {
            _name = "Abusable Token Privileges";

            int TokenInfLength = 0;
            IntPtr ThisHandle = WindowsIdentity.GetCurrent().Token;
            GetTokenInformation(ThisHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            if (GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, out TokenInfLength))
            {
                TOKEN_PRIVILEGES ThisPrivilegeSet = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES));
                for (int index = 0; index < ThisPrivilegeSet.PrivilegeCount; index++)
                {
                    LUID_AND_ATTRIBUTES laa = ThisPrivilegeSet.Privileges[index];
                    System.Text.StringBuilder StrBuilder = new System.Text.StringBuilder();
                    int LuidNameLen = 0;
                    IntPtr LuidPointer = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));
                    Marshal.StructureToPtr(laa.Luid, LuidPointer, true);
                    LookupPrivilegeName(null, LuidPointer, null, ref LuidNameLen);
                    StrBuilder.EnsureCapacity(LuidNameLen + 1);
                    if (LookupPrivilegeName(null, LuidPointer, StrBuilder, ref LuidNameLen))
                    {
                        string privilege = StrBuilder.ToString();
                        foreach (string SpecialPrivilege in _specialPrivileges)
                        {
                            if (privilege == SpecialPrivilege)
                            {
                                _isVulnerable = true;
                                _details.Add($"{privilege}: {(LuidAttributes)laa.Attributes}");
                            }
                        }
                    }
                    Marshal.FreeHGlobal(LuidPointer);
                }
            }
            Marshal.FreeHGlobal(TokenInformation);
        }
    }
}
