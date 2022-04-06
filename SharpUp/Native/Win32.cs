using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SharpUp.Native
{
    public static class Win32
    {
        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            IntPtr lpLuid,
            System.Text.StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool QueryServiceObjectSecurity(
            IntPtr serviceHandle,
            System.Security.AccessControl.SecurityInfos secInfo,
            byte[] lpSecDesrBuf,
            uint bufSize,
            out uint bufSizeNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        // PInvoke structures/contants
        public const uint SE_GROUP_LOGON_ID = 0xC0000000; // from winnt.h
        public const int TokenGroups = 2; // from TOKEN_INFORMATION_CLASS
        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_GROUPS
        {
            public int GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] Groups;
        };

        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 35)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [Flags]
        public enum LuidAttributes : uint
        {
            DISABLED = 0x00000000,
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
            SE_PRIVILEGE_ENABLED = 0x00000002,
            SE_PRIVILEGE_REMOVED = 0x00000004,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000
        }

        [Flags]
        public enum ServiceAccessRights : uint
        {
            QueryConfig = 0x00000001,
            ChangeConfig = 0x00000002,
            QueryStatus = 0x00000004,
            EnumerateDependents = 0x00000008,
            Start = 0x00000010,
            Stop = 0x00000020,
            PauseContinue = 0x00000040,
            Interrogate = 0x00000080,
            UserDefinedControl = 0x00000100,
            Delete = 0x00010000,
            ReadControl = 0x00020000,
            WriteDac = 0x00040000,
            WriteOwner = 0x00080000,
            Synchronize = 0x00100000,
            AccessSystemSecurity = 0x01000000,
            GenericAll = 0x10000000,
            GenericExecute = 0x20000000,
            GenericWrite = 0x40000000,
            GenericRead = 0x80000000,
            AllAccess = 0x000F01FF,
        }
    }
}
