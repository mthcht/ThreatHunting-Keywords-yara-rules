rule SharpUp
{
    meta:
        description = "Detection patterns for the tool 'SharpUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpUp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string1 = " audit AlwaysInstallElevated" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string2 = " audit CachedGPPPassword" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string3 = " audit DomainGPPPassword" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string4 = " audit HijackablePaths" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string5 = " audit McAfeeSitelistFiles" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string6 = " audit ModifiableScheduledTask" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string7 = " audit ModifiableServiceBinaries" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string8 = " audit ModifiableServiceRegistryKeys" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string9 = " audit ModifiableServices" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string10 = " audit ProcessDLLHijack" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string11 = " audit RegistryAutoLogons" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string12 = " audit RegistryAutoruns" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string13 = " audit TokenPrivileges" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string14 = " audit UnattendedInstallFiles" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string15 = " audit UnquotedServicePath" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string16 = /\.exe\sAlwaysInstallElevated/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string17 = /\.exe\saudit\sHijackablePaths/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string18 = /\.exe\saudit\sModifiableServices/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string19 = /\.exe\sCachedGPPPassword/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string20 = /\.exe\sDomainGPPPassword/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string21 = /\.exe\sHijackablePaths/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string22 = /\.exe\sMcAfeeSitelistFiles/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string23 = /\.exe\sModifiableScheduledTask/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string24 = /\.exe\sModifiableServiceBinaries/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string25 = /\.exe\sModifiableServiceRegistryKeys/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string26 = /\.exe\sModifiableServices/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string27 = /\.exe\sProcessDLLHijack/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string28 = /\.exe\sRegistryAutoLogons/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string29 = /\.exe\sRegistryAutoruns/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string30 = /\.exe\sTokenPrivileges/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string31 = /\.exe\sUnattendedInstallFiles/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string32 = /\.exe\sUnquotedServicePath/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string33 = /\/SharpUp\.exe/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string34 = /\/SharpUp\.git/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string35 = /\[\!\]\sModifialbe\sscheduled\stasks\swere\snot\sevaluated\sdue\sto\spermissions/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string36 = /\[\+\]\sHijackable\sDLL\:\s/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string37 = /\[\+\]\sPotenatially\sHijackable\sDLL\:\s/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string38 = /\\AlwaysInstallElevated\.cs/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string39 = /\\CachedGPPPassword\.cs/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string40 = /\\DomainGPPPassword\.cs/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string41 = /\\HijackablePaths\.cs/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string42 = /\\ProcessDLLHijack\.cs/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string43 = /\\SharpUp\.csproj/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string44 = /\\SharpUp\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string45 = /\\SharpUp\.pdb/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string46 = /\\SharpUp\.sln/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string47 = /\\SharpUp\\/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string48 = /\\SharpUp\-master/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string49 = /\\UnquotedServicePath\.cs/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string50 = /\]\sAlready\sin\shigh\sintegrity\,\sno\sneed\sto\sprivesc\!/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string51 = /\]\sCompleted\sPrivesc\sChecks\sin\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string52 = /\]\sIn\smedium\sintegrity\sbut\suser\sis\sa\slocal\sadministrator\-\sUAC\scan\sbe\sbypassed\./ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string53 = "=== SharpUp: Running Privilege Escalation Checks ===" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string54 = ">SharpUp<" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string55 = "Already in high integrity, no need to privesc!" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string56 = "FDD654F5-5C54-4D93-BF8E-FAF11B00E3E9" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string57 = "GhostPack/SharpUp" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string58 = "In medium integrity but user is a local administrator- UAC can be bypassed" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string59 = "ParseGPPPasswordFromXml" nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string60 = /SharpUp\.exe/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string61 = /using\sSharpUp\.Classes/ nocase ascii wide
        // Description: SharpUp is a C# port of various PowerUp functionality. Currently. only the most common checks have been ported. no weaponization functions have yet been implemented.
        // Reference: https://github.com/GhostPack/SharpUp
        $string62 = /using\sstatic\sSharpUp\.Utilities/ nocase ascii wide
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
