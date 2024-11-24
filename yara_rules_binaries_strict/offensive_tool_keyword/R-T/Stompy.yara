rule Stompy
{
    meta:
        description = "Detection patterns for the tool 'Stompy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stompy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string1 = /\sStompy\.ps1/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string2 = /\sStomPY\.py\s/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string3 = /\.\/GoStompy\s/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string4 = /\.exe.{0,100}\s\-path\s.{0,100}\s\-newTimestamp\s.{0,100}\s\-username\s.{0,100}\s\-password\s/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string5 = /\/GoStompy\.go/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string6 = /\/Stompy\.git/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string7 = /\/Stompy\.ps1/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string8 = /\/StomPY\.py/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string9 = /\\GoStompy\.go/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string10 = /\\Stompy\.ps1/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string11 = /\\StomPY\.py/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string12 = /\\Stompy\-main\\/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string13 = "784F8029-4D72-4363-9638-5A8D11545494" nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string14 = /build\sGoStompy\.go/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string15 = "Invoke-Stompy" nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string16 = /StompySharps\.csproj/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string17 = /StompySharps\.exe/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string18 = /StompySharps\.sln/ nocase ascii wide
        // Description: Timestomp Tool to flatten MAC times with a specific timestamp
        // Reference: https://github.com/ZephrFish/Stompy
        $string19 = "ZephrFish/Stompy" nocase ascii wide
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
