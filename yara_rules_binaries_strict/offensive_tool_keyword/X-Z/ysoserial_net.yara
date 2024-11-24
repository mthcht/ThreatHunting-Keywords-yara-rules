rule ysoserial_net
{
    meta:
        description = "Detection patterns for the tool 'ysoserial.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ysoserial.net"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string1 = /\s\-c\s.{0,100}ExploitClass\.cs.{0,100}System\.dll/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string2 = /\s\-\-cve\=.{0,100}\s\-\-command/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string3 = " -g ActivitySurrogateSelector" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string4 = " -g ClaimsPrincipal " nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string5 = " -g PSObject " nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string6 = " -g TextFormattingRunProperties " nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string7 = " --gadget ActivitySurrogateSelector" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string8 = " --gadget ClaimsPrincipal " nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string9 = " --gadget PSObject " nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string10 = /\s\-m\srun_command\s\-c\s.{0,100}\.exe/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string11 = " -p ActivatorUrl" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string12 = " -p Altserialization" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string13 = " -p DotNetNuke" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string14 = " -p SessionSecurityTokenHandler" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string15 = " -p TransactionManagerReenlist" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string16 = /\/ghostfile\.aspx/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string17 = "/ysoserial/" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string18 = /\\windows\\temp\\ncat\.exe\s\-nv\s/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string19 = /\\ysoserial\\/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string20 = /echo\s123\s\>\sc\:\\windows\\temp\\test\.txt/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string21 = "-f BinaryFormatter -g PSObject -o base64 -c " nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string22 = /\-f\sJson\.Net\s\-g\sObjectDataProvider\s\-o\sraw\s\-c\s/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string23 = "fakepath31337" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string24 = /GhostWebShell\.cs/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string25 = /MessageBox\.Show.{0,100}Pwned/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string26 = /ModifiedVulnerableBinaryFormatters\\info\.txt/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string27 = "PCVAIExhbmd1YWdlPSJDIyIlPgpUaGlzIGlzIHRoZSBhdHRhY2tlcidzIGZpbGUgPGJyLz4KUnVubmluZyBvbiB0aGUgc2VydmVyIGlmIGA8JT0xMzM4LTElPmAgaXMgMTMzNy4" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string28 = "TestConsoleApp_YSONET" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string29 = "X-YSOSERIAL-NET" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string30 = "ysoserial -" nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string31 = /ysoserial\-.{0,100}\.zip/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string32 = /ysoserial\.exe/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string33 = /ysoserial\.net/ nocase ascii wide
        // Description: Deserialization payload generator for a variety of .NET formatters
        // Reference: https://github.com/pwntester/ysoserial.net
        $string34 = /ysoserial\.sln/ nocase ascii wide
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
