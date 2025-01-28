rule silenttrinity
{
    meta:
        description = "Detection patterns for the tool 'silenttrinity' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "silenttrinity"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string1 = /\ssilenttrinity\./ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string2 = " st client wss://" nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string3 = " st teamserver " nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string4 = /\.\\stager\.ps1/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string5 = /\/shellcode\.bin/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string6 = /\/shellcode\.hex/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string7 = /\/silenttrinity\/.{0,100}\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string8 = /_peloader\.dll/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string9 = /alwaysinstallelevated\./ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string10 = /bypassUAC.{0,100}\.boo/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string11 = /bypassUAC.{0,100}\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string12 = "core/teamserver/stagers/" nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string13 = /credphisher\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string14 = /dumpVaultCredentials\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string15 = /excelshellinject\./ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string16 = /hijackCLSIDpersistence\./ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string17 = /impersonateprocess\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string18 = /impersonateuser\.boo/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string19 = /impersonateuser\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string20 = /injectremote\.boo/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string21 = /kerberoasting\.boo/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string22 = /mouseshaker\./ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string23 = /netloggedonusers\./ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string24 = /pathhijack\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string25 = /portscanner\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string26 = /posh_stageless\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string27 = "python 3 st teamserver " nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string28 = /python\sst\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string29 = "python3 st client wss://" nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string30 = /python3\sst\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string31 = "SILENTTRINITY" nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string32 = /silenttrinity.{0,100}\.dll/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string33 = /specialtokengroupprivs\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string34 = /startupfolderperistence\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string35 = "use powershell_stageless" nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string36 = "use safetykatz" nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string37 = /vnperistence\.py/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string38 = /WMIExecHash\./ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string39 = /WMIExecHash\.boo/ nocase ascii wide
        // Description: SILENTTRINITY is modern. asynchronous. multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. Its the culmination of an extensive amount of research into using embedded third-party .NET scripting languages to dynamically call .NET APIs. a technique the author coined as BYOI (Bring Your Own Interpreter). The aim of this tool and the BYOI concept is to shift the paradigm back to PowerShell style like attacks (as it offers much more flexibility over traditional C# tradecraft) only without using PowerShell in anyway.
        // Reference: https://github.com/byt3bl33d3r/SILENTTRINITY
        $string40 = /wmipersistence\.py/ nocase ascii wide
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
