rule SharpSecDump
{
    meta:
        description = "Detection patterns for the tool 'SharpSecDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSecDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string1 = /\/SharpSecDump\.git/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string2 = "4bb5b8961566bdbdc3787a847a55730ce32d1822677bcd7c412cf2d7f54262fd" nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string3 = "E2FDD6CC-9886-456C-9021-EE2C47CF67B7" nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string4 = "fbee25dd2d6b1faf917f4f6a90113e3c520125f325915b7dd70f304dd2dab4b1" nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string5 = "G0ldenGunSec/SharpSecDump" nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string6 = /secretsdump\.py/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string7 = "SharpSecDump Info" nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string8 = /SharpSecDump\.csproj/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string9 = /SharpSecDump\.exe/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string10 = /SharpSecDump\.sln/ nocase ascii wide
        // Description: .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py
        // Reference: https://github.com/G0ldenGunSec/SharpSecDump
        $string11 = "SharpSecDump-master" nocase ascii wide
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
