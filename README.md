# SharpUp

----

SharpUp is a C# port of various [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) functionality. Currently, only the most common checks have been ported; no weaponization functions have yet been implemented.

[@harmj0y](https://twitter.com/harmj0y) is the primary author.

SharpUp is licensed under the BSD 3-Clause license.

## Usage

```
SharpUp.exe [audit] [check1] [check2]...

    audit   - Specifies whether or not to enable audit mode. If enabled, SharpUp will run vulenrability checks
              regardless if the process is in high integrity or the user is in the local administrator's group.
              If no checks are specified, audit will run all checks. Otherwise, each check following audit will
              be ran.

    check*  - The individual vulnerability check to be ran. Must be one of the following:

              - AlwaysInstallElevated
              - CachedGPPPassword
              - DomainGPPPassword
              - HijackablePaths
              - McAfeeSitelistFiles
              - ModifiableScheduledTask
              - ModifiableServiceBinaries
              - ModifiableServiceRegistryKeys
              - ModifiableServices
              - ProcessDLLHijack
              - RegistryAutoLogons
              - RegistryAutoruns
              - TokenPrivileges
              - UnattendedInstallFiles
              - UnquotedServicePath
            

    Examples:
        SharpUp.exe audit
            -> Runs all vulnerability checks regardless of integrity level or group membership.
        
        SharpUp.exe HijackablePaths
            -> Check only if there are modifiable paths in the user's %PATH% variable.

        SharpUp.exe audit HijackablePaths
            -> Check only for modifiable paths in the user's %PATH% regardless of integrity level or group membership. 
```

## Compile Instructions

We are not planning on releasing binaries for SharpUp, so you will have to compile yourself :)

SharpUp has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.

## Acknowledgments

SharpUp incorporates various code C# snippets and bits of PoCs found throughout research for its capabilities. These snippets and authors are highlighted in the appropriate locations in the source code, and include:

* [Igor Korkhov's code to retrieve current token group information](https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418)
* [JGU's snippet on file/folder ACL right comparison](https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345)
* [Rod Stephens' pattern for recursive file enumeration](http://csharphelper.com/blog/2015/06/find-files-that-match-multiple-patterns-in-c/)
* [SwDevMan81's snippet for enumerating current token privileges](https://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni)
* [Nikki Locke's code for querying service security descriptors](https://stackoverflow.com/questions/15771998/how-to-give-a-user-permission-to-start-and-stop-a-particular-service-using-c-sha/15796352#15796352)
* [Raika](https://github.com/Raikia) for providing example unquoted service path search code.
* [RemiEscourrou](https://github.com/RemiEscourrou) for contributing additional ACE checking code and example modifiable service registry key code.
* [Coder666](https://github.com/Coder666) for adding ACE filtering code to filter only ACEs with access allowed.
* [vysecurity](https://github.com/vysecurity) for providing Registry Auto Logon and Domain GPP Password example code.
* [djhohnstein](https://github.com/djhohnstein) for merging in several outdated PRs and refactoring the entire code base.