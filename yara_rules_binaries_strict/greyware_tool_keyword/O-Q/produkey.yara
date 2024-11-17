rule produkey
{
    meta:
        description = "Detection patterns for the tool 'produkey' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "produkey"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string1 = /\/ProduKey\.exe/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string2 = /\\ProduKey\.exe/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string3 = /produkey\.zip/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string4 = /produkey_setup\.exe/ nocase ascii wide
        // Description: ProduKey is a small utility that displays the ProductID and the CD-Key of Microsoft Office (Microsoft Office 2003. Microsoft Office 2007). Windows (Including Windows 8/7/Vista). Exchange Server. and SQL Server installed on your computer. You can view this information for your current running operating system. or for another operating system/computer - by using command-line options. This utility can be useful if you lost the product key of your Windows/Office. and you want to reinstall it on your computer.
        // Reference: https://www.nirsoft.net/utils/product_cd_key_viewer.html
        $string5 = /produkey\-x64\.zip/ nocase ascii wide
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
