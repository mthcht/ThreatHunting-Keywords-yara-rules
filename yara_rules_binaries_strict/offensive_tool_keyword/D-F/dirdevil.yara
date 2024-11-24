rule dirdevil
{
    meta:
        description = "Detection patterns for the tool 'dirdevil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirdevil"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string1 = /\sdirdevil\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string2 = /\sdirdevil_decoder_mini\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string3 = /\sdirdevil_decoder_only\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string4 = /\/dirdevil\.git/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string5 = /\/dirdevil\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string6 = /\/dirdevil_decoder_mini\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string7 = /\/dirdevil_decoder_only\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string8 = "@2024 nyxgeek - TrustedSec" nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string9 = /\\dirdevil\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string10 = /\\dirdevil_decoder_mini\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string11 = /\\dirdevil_decoder_only\.ps1/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string12 = /\\trustedsec\\Downloads\\putty\.exe/ nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string13 = "0ad1f9bb7c3b296339d3c3f9bb4338b79bfb9f051fbb8749c411c44195e68d35" nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string14 = "3e6740a3e67c207dc53df0daf1c5717def2b267119c75ff0cf6e36585efc332a" nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string15 = "41f73755bc80ff028571e3496dd851447cc69f428045223deb717173e5c44e69" nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string16 = "dirdevil - PowerShell to hide data in directory structures" nocase ascii wide
        // Description: PowerShell to hide data in directory structures
        // Reference: https://github.com/nyxgeek/dirdevil
        $string17 = "nyxgeek/dirdevil" nocase ascii wide
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
