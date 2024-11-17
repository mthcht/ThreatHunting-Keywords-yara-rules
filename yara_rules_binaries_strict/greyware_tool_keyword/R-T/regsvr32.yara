rule regsvr32
{
    meta:
        description = "Detection patterns for the tool 'regsvr32' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "regsvr32"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious service creation executing a desktop.ini file observed in a malware sample
        // Reference: https://www.virustotal.com/gui/file/faca8b6f046dad8f0e27a75fa2dc5477d3ccf44adced64481ef1b0dd968b4b0e/behavior
        $string1 = /cmd\s\/c\sregsvr32\.exe\s\/s\sC\:\\.{0,100}\\desktop\.ini\\"\sstart\=\sauto/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string2 = /regsvr32\sAmsiProvider\.dll/ nocase ascii wide
        // Description: suspicious service creation executing a desktop.ini file observed in a malware sample
        // Reference: https://www.virustotal.com/gui/file/faca8b6f046dad8f0e27a75fa2dc5477d3ccf44adced64481ef1b0dd968b4b0e/behavior
        $string3 = /sc\screate\s.{0,100}cmd\s\/c\sregsvr32\.exe\s\/s\s.{0,100}\\desktop\.ini/ nocase ascii wide
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
