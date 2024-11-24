rule SharpCOM
{
    meta:
        description = "Detection patterns for the tool 'SharpCOM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCOM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string1 = /\.exe\s\-\-Method\sShellWindows\s\-\-ComputerName\s.{0,100}\s\-\-Command\s/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string2 = /\/SharpCOM\.exe/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string3 = /\/SharpCOM\.git/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string4 = /\\SharpCOM\.csproj/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string5 = /\\SharpCOM\.exe/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string6 = /\\SharpCOM\.sln/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string7 = ">SharpCOM<" nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string8 = "0c9c1d4a02cdc9cac7b19c0b055468d9c04714c00bd3df254490ecf4953c5c95" nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string9 = "51960F7D-76FE-499F-AFBD-ACABD7BA50D1" nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string10 = "d01dcb5cb218aa1cf3e7e942a101d371090db7dc7a29acdd905b0932e87c6668" nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string11 = /Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string12 = "rvrsh3ll/SharpCOM" nocase ascii wide
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
