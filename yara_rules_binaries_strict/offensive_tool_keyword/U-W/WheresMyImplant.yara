rule WheresMyImplant
{
    meta:
        description = "Detection patterns for the tool 'WheresMyImplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WheresMyImplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string1 = /\/C2\/Beacon\/.{0,100}\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string2 = /\/Inject\/Dll\/LoadDll/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string3 = /\/Inject\/PE\/.{0,100}\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string4 = /\/Inject\/ShellCode\/.{0,100}\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string5 = /\/KeyLogger\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string6 = /\/Lateral\/SMB\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string7 = /\/LoadDllRemote\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string8 = /\/PE\/InjectPE\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string9 = /\/Persistence\/InstallUtil\./ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string10 = /\/WheresMyImplant\// nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string11 = /\\WheresMyImplant/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string12 = /0xbadjuju\/WheresMyImplant/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string13 = /Collection\/MiniDumpWriteDump\./ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string14 = /Credentials\/CacheDump\./ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string15 = /Credentials\/LSASecrets\./ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string16 = /DumpBrowserHistory/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string17 = /Empire\.Agent\.Coms\./ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string18 = /Empire\.Agent\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string19 = /Empire\.Agent\.Jobs\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string20 = /Empire\.Agent\.Stager\./ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string21 = /InjectPERemote\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string22 = /InjectPEWMIFSRemote/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string23 = /InjectShellCode\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string24 = /InjectShellCodeRemote\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string25 = /InjectShellCodeWMIFSB64/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string26 = /Lateral\/DCom\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string27 = /Lateral\/PSExec\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string28 = /Lateral\/SMBClient\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string29 = /Lateral\/SMBClientDelete\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string30 = /Lateral\/SMBClientGet\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string31 = /Lateral\/SMBClientPut\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string32 = /Lateral\/WMIExec\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string33 = /namespace\sWheresMyImplant/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string34 = /Persistence\/InstallWMI/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string35 = /PTHSMBClientDelete/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string36 = /PTHSMBClientGet/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string37 = /PTHSMBClientList/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string38 = /PTHSMBClientPut/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string39 = /PTHSMBExec/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string40 = /PTHWMIExec/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string41 = /root\\cimv2\:Win32_Implant/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string42 = /StartWebServiceBeacon/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string43 = /WheresMyImplant\.cs/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string44 = /WheresMyImplant\.git/ nocase ascii wide
        // Description: A Bring Your Own Land Toolkit that Doubles as a WMI Provider
        // Reference: https://github.com/0xbadjuju/WheresMyImplant
        $string45 = /WheresMyImplant\.sln/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
