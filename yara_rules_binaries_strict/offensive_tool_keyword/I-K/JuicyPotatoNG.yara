rule JuicyPotatoNG
{
    meta:
        description = "Detection patterns for the tool 'JuicyPotatoNG' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JuicyPotatoNG"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string1 = " JuicyPotatoNG" nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string2 = /\.exe\s\-l\s.{0,100}\s\-c\s\{B91D5831\-B1BD\-4608\-8198\-D72E155020F7\}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string3 = /\.exe\s\-l\s.{0,100}\s\-c\s\{F7FD3FD6\-9994\-452D\-8DA7\-9A8FD87AEEF4\}\s\-a/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string4 = /\/JuicyPotatoNG\.git/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string5 = /\[\-\]\sExploit\sfailed\!\s/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string6 = /\[\+\]\sExploit\ssuccessful\!\s/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string7 = /\\JuicyPotatoNG/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string8 = /\]\sBruteforcing\s\%d\sCLSIDs/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string9 = "261f880e-4bee-428d-9f64-c29292002c19" nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string10 = "antonioCoco/JuicyPotatoNG" nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string11 = /BruteforceCLSIDs\./ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string12 = "c5af796b44a3d3d09e184ef622ad002b8298696c2de139392fd35898f5073527" nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string13 = "C73A4893-A5D1-44C8-900C-7B8850BBD2EC" nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string14 = /JuicyPotatoNG\.cpp/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string15 = /JuicyPotatoNG\.exe/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string16 = /JuicyPotatoNG\.sln/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string17 = /JuicyPotatoNG\.txt/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string18 = /JuicyPotatoNG\.zip/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string19 = "JuicyPotatoNG-main" nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string20 = /PotatoTrigger\.cpp/ nocase ascii wide
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
