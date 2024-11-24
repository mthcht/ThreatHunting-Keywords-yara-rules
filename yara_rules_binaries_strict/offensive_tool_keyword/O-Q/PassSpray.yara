rule PassSpray
{
    meta:
        description = "Detection patterns for the tool 'PassSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string1 = /\sPassSpray\.ps1/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string2 = /\/PassSpray\.git/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string3 = /\/PassSpray\.ps1/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string4 = /\\PassSpray\.ps1/ nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string5 = "24d7bda466850d93fc1883a3937e1317fbb3f9e631ab0d2a4fa0b45c2c21c24f" nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string6 = "Invoke-PassSpray" nocase ascii wide
        // Description: Domain Password Spray
        // Reference: https://github.com/Leo4j/PassSpray
        $string7 = "Leo4j/PassSpray" nocase ascii wide
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
