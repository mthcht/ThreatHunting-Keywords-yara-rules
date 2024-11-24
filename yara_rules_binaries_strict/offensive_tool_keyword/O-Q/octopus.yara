rule octopus
{
    meta:
        description = "Detection patterns for the tool 'octopus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "octopus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string1 = " deploy_cobalt_beacon" nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string2 = /\soctopus\.py/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string3 = /\.\/.{0,100}octopus\.py/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string4 = /\/agent\.ps1\.oct/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string5 = /\/octopus\.asm/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string6 = /\/Octopus\.git/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string7 = /\/octopusx64\.asm/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string8 = /\/weblistener\.py/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string9 = /ASBBypass\.ps1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string10 = "generate_hta operation1" nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string11 = "generate_powershell operation1" nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string12 = "generate_spoofed_args_exe" nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string13 = /generate_unmanaged_exe\soperation1\s.{0,100}\.exe/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string14 = "generate_x64_shellcode" nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string15 = "generate_x86_shellcode" nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string16 = /ILBypass\.ps1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string17 = /listen_http\s0\.0\.0\.0\s8080\s.{0,100}\.php\soperation1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string18 = "mhaskar/Octopus" nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string19 = /octopus\.py\s/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
