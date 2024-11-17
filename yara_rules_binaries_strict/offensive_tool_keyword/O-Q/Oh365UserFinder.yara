rule Oh365UserFinder
{
    meta:
        description = "Detection patterns for the tool 'Oh365UserFinder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Oh365UserFinder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string1 = /\/Oh365UserFinder/ nocase ascii wide
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string2 = /Oh365UserFinder\.git/ nocase ascii wide
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string3 = /oh365userfinder\.py/ nocase ascii wide
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string4 = /Oh365UserFinder\-main/ nocase ascii wide
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
