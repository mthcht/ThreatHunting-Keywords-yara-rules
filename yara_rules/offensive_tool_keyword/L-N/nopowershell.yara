rule nopowershell
{
    meta:
        description = "Detection patterns for the tool 'nopowershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nopowershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string1 = /.{0,1000}\/nopowershell\.git.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string2 = /.{0,1000}\/NoPowerShell\/.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string3 = /.{0,1000}\\CompressArchiveCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string4 = /.{0,1000}\\CopyItemCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string5 = /.{0,1000}\\DllExport\.bat.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string6 = /.{0,1000}\\ExpandArchiveCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string7 = /.{0,1000}\\ExportCsvCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string8 = /.{0,1000}\\FormatListCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string9 = /.{0,1000}\\FormatTableCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string10 = /.{0,1000}\\GetADGroupCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string11 = /.{0,1000}\\GetADGroupMemberCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string12 = /.{0,1000}\\GetADObjectCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string13 = /.{0,1000}\\GetADTrustCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string14 = /.{0,1000}\\GetADUserCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string15 = /.{0,1000}\\GetChildItemCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string16 = /.{0,1000}\\GetClipboardCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string17 = /.{0,1000}\\GetCommandCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string18 = /.{0,1000}\\GetComputerInfoCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string19 = /.{0,1000}\\GetContentCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string20 = /.{0,1000}\\GetDnsClientCacheCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string21 = /.{0,1000}\\GetHelpCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string22 = /.{0,1000}\\GetHotFixCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string23 = /.{0,1000}\\GetItemPropertyCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string24 = /.{0,1000}\\GetItemPropertyValueCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string25 = /.{0,1000}\\GetLocalGroupCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string26 = /.{0,1000}\\GetLocalGroupMemberCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string27 = /.{0,1000}\\GetLocalUserCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string28 = /.{0,1000}\\GetNetIPAddressCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string29 = /.{0,1000}\\GetNetNeighborCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string30 = /.{0,1000}\\GetNetRouteCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string31 = /.{0,1000}\\GetNetTCPConnectionCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string32 = /.{0,1000}\\GetProcessCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string33 = /.{0,1000}\\GetPSDriveCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string34 = /.{0,1000}\\GetRemoteSmbShareCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string35 = /.{0,1000}\\GetSmbMappingCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string36 = /.{0,1000}\\GetSmbShareCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string37 = /.{0,1000}\\GetWhoamiCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string38 = /.{0,1000}\\GetWinStationCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string39 = /.{0,1000}\\GetWmiObjectCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string40 = /.{0,1000}\\InvokeWebRequestCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string41 = /.{0,1000}\\InvokeWmiMethodCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string42 = /.{0,1000}\\MeasureObjectCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string43 = /.{0,1000}\\NoPowerShell.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string44 = /.{0,1000}\\OutFileCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string45 = /.{0,1000}\\RemoveItemCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string46 = /.{0,1000}\\ResolveDnsNameCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string47 = /.{0,1000}\\SelectObjectCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string48 = /.{0,1000}\\SetClipboardCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string49 = /.{0,1000}\\SortObjectCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string50 = /.{0,1000}\\StopProcessCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string51 = /.{0,1000}\\TestNetConnectionCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string52 = /.{0,1000}\\Tmp\\nc\.exe.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string53 = /.{0,1000}\\Tmp\\netcat\.exe.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string54 = /.{0,1000}\\WhereObjectCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string55 = /.{0,1000}\\Windows\\System32\\nc\.exe.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string56 = /.{0,1000}\\WriteOutputCommand\.cs/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string57 = /.{0,1000}\=\=\sNoPowerShell\sv.{0,1000}\s\=\=.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string58 = /.{0,1000}\=\=\sNoPowerShell\sv.{0,1000}\s\=\=.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string59 = /.{0,1000}555AD0AC\-1FDB\-4016\-8257\-170A74CB2F55.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string60 = /.{0,1000}555AD0AC\-1FDB\-4016\-8257\-170A74CB2F55.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string61 = /.{0,1000}bitsadmin\/nopowershell.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string62 = /.{0,1000}BOFNET\.Bofs\.Jobs.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string63 = /.{0,1000}bofnet\.cna.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string64 = /.{0,1000}BOFNET\.dll.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string65 = /.{0,1000}bofnet_execute\s.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string66 = /.{0,1000}bofnet_execute\.cpp.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string67 = /.{0,1000}bofnet_execute\.cpp\.x64\.obj.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string68 = /.{0,1000}bofnet_execute\.cpp\.x64\.obj.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string69 = /.{0,1000}bofnet_execute\.cpp\.x86\.obj.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string70 = /.{0,1000}bofnet_execute\.cpp\.x86\.obj.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string71 = /.{0,1000}bofnet_load\s.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string72 = /.{0,1000}GetWhoamiCommand\.cs.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string73 = /.{0,1000}https:\/\/github\.com\/bitsadmin\/.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string74 = /.{0,1000}NoPowerShell\.cna.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string75 = /.{0,1000}NoPowerShell\.Commands.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string76 = /.{0,1000}NoPowerShell\.Commands\.Management.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string77 = /.{0,1000}NoPowerShell\.csproj.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string78 = /.{0,1000}NoPowerShell\.dll.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string79 = /.{0,1000}NoPowerShell\.exe.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string80 = /.{0,1000}NoPowerShell\.sln.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string81 = /.{0,1000}NoPowerShell_trunk\.zip.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string82 = /.{0,1000}NoPowerShell32\.dll.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string83 = /.{0,1000}NoPowerShell64\.dll.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string84 = /.{0,1000}NoPowerShellDll\..{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string85 = /.{0,1000}nps\swhoami.{0,1000}/ nocase ascii wide
        // Description: NoPowerShell is a tool implemented in C# which supports executing PowerShell-like commands while remaining invisible to any PowerShell logging mechanisms. This .NET Framework 2 compatible binary can be loaded in Cobalt Strike to execute commands in-memory. No System.Management.Automation.dll is used. only native .NET libraries. An alternative usecase for NoPowerShell is to launch it as a DLL via rundll32.exe: rundll32 NoPowerShell.dll.main.
        // Reference: https://github.com/bitsadmin/nopowershell
        $string86 = /.{0,1000}PublicKeyToken\=8337224c9ad9e356.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
