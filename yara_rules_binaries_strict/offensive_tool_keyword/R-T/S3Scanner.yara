rule S3Scanner
{
    meta:
        description = "Detection patterns for the tool 'S3Scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S3Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string1 = /\sdump\s\-\-bucket\s.{0,100}\-\-dump\-dir/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string2 = /\s\-\-threads\s.{0,100}\sscan\s\-\-buckets\-file.{0,100}\s/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string3 = /\/S3Scanner\.git/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string4 = "install s3scanner" nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string5 = "python3 -m S3Scanner" nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string6 = "s3scanner -" nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string7 = "s3scanner dump " nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string8 = "s3scanner scan " nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string9 = "S3Scanner-master" nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string10 = "sa7mon/S3Scanner" nocase ascii wide
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
