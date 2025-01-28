rule TotalRecall
{
    meta:
        description = "Detection patterns for the tool 'TotalRecall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TotalRecall"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string1 = " Recall folder found: " nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string2 = /\s\-\-search\spassword\s\-\-from_date\s.{0,100}\s\-\-to_date\s/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string3 = /\stotalrecall\.py/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string4 = /\sWindows\sRecall\sfeature\sfound\.\sDo\syou\swant\sto\sproceed\swith\sthe\sextraction\?/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string5 = /\sWindows\sRecall\sfeature\snot\sfound\.\sNothing\sto\sextract/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string6 = /\/TotalRecall\.git/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string7 = /\/totalrecall\.py/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string8 = /\/TotalRecall\.txt/
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string9 = /\\2024\-.{0,100}_Recall_Extraction\\/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string10 = /\\2025\-.{0,100}_Recall_Extraction\\/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string11 = /\\totalrecall\.py/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string12 = /\\TotalRecall\.txt/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string13 = /\\TotalRecall\\.{0,100}_Recall_Extraction/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string14 = "353f18e314f024ceea013bd97c140e09fd4ac715bf9ac7c965d0b89845dffcf0" nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string15 = /C\:\\\\Users\\\\\{username\}\\\\AppData\\\\Local\\\\CoreAIPlatform\.00\\\\UKP/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string16 = /extraction_folder.{0,100}TotalRecall\.txt/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string17 = /SELECT\sWindowTitle\,\sTimeStamp\,\sImageToken\s.{0,100}FROM\sWindowCapture/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string18 = "xaitax/TotalRecall" nocase ascii wide
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
