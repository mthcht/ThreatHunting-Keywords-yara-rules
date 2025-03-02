rule Lsassx
{
    meta:
        description = "Detection patterns for the tool 'Lsassx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lsassx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string1 = /\sLsassx\.ps1/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string2 = /\sLsassx\-OBF\.ps1/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string3 = "# Using reflection to dump LSASS in-memory with stealth" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string4 = /\/Lsassx\.git/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string5 = /\/Lsassx\.ps1/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string6 = /\/Lsassx\-OBF\.ps1/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string7 = /\[\!\]\sIn\-memory\sLSASS\sdump\smethod\sfailed\:\s/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string8 = /\[\!\]\sLSASS\sdump\sfailed\s/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string9 = /\[\+\]\sLSASS\sdump\screated\ssuccessfully\./ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string10 = /\[Text\.Encoding\]\:\:Unicode\.GetString\(\[Convert\]\:\:FromBase64String\(\'bABzAGEAcwBzAA\=\=/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string11 = /\\Lsassx\.ps1/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string12 = /\\Lsassx\-main/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string13 = /\\Lsassx\-OBF\.ps1/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string14 = /\]\sAttempting\sstealthy\sLSASS\sdump/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string15 = "a60a04cda101deaab5c2aa8b25c715fffc7a4f3e9813fa6d53a5b25dd4126fe2" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string16 = "af6d177df40fcf715f752557c9fd2483a5e194c1c468625a76a4862632db5cb6" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string17 = /C\:\\Users\\Public\\backup\.enc/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string18 = /C\:\\Users\\Public\\syslog\.dat/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string19 = /C\:\\Users\\Public\\syslog\.zip/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string20 = /decoded_lsass\.dmp/ nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string21 = "IAAgACAAIAB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQA7AA0ACgAgACAAIAAgAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AUgB1AG4AdABpAG0AZQAuAEkAbgB0AGUAcgBvAHAAUwBlAHIAdgBpAGMAZQBzADsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABMAFMAQQBTAFMARAB1AG0AcAA" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string22 = "public class LSASSDump" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string23 = "QwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABiAGEAYwBrAHUAcAAuAGUAbgBjAA==" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string24 = "QwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABzAHkAcwBsAG8AZwAuAGQAYQB0AA==" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string25 = "QwA6AFwAVQBzAGUAcgBzAFwAUAB1AGIAbABpAGMAXABzAHkAcwBsAG8AZwAuAHoAaQBwAA==" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string26 = "WwAhAF0AIABJAG4ALQBtAGUAbQBvAHIAeQAgAEwAUwBBAFMAUwAgAGQAdQBtAHAAIABtAGUAdABoAG8AZAAgAGYAYQBpAGwAZQBkADoAIAAkAF8A" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string27 = "WwAhAF0AIABMAFMAQQBTAFMAIABkAHUAbQBwACAAZgBhAGkAbABlAGQAIAB1AHMAaQBuAGcAIABzAHQAZQBhAGwAdABoACAAbQBlAHQAaABvAGQALgA=" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string28 = "WwAhAF0AIABMAFMAQQBTAFMAIABkAHUAbQBwACAAZgBhAGkAbABlAGQALgAgAEUAeABpAHQAaQBuAGcAIABzAGMAcgBpAHAAdAAuAA==" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string29 = "WwAqAF0AIABBAHQAdABlAG0AcAB0AGkAbgBnACAAcwB0AGUAYQBsAHQAaAB5ACAATABTAEEAUwBTACAAZAB1AG0AcAAgAHUAcwBpAG4AZwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAByAGUAZgBsAGUAYwB0AGkAbwBuAC4ALgAuAA==" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string30 = "WwAqAF0AIABEAG8AbgBlAC4AIABDAGgAZQBjAGsAIAAkAHsAXwAvAD0AXABfAC8AXABfAF8ALwBcAF8ALwA9AFwALwA9AH0AIABmAG8AcgAgAHQAaABlACAAZgBpAG4AYQBsACAAYQByAGMAaABpAHYAZQAgAGkAZgAgAHMAdQBjAGMAZQBzAHMAZgB1AGwALgA=" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string31 = "WwArAF0AIABDAG8AbQBwAHIAZQBzAHMAaQBvAG4AIABjAG8AbQBwAGwAZQB0AGUAZAA6ACAAJAB7AF8ALwA9AFwAXwAvAFwAXwBfAC8AXABfAC8APQBcAC8APQB9AA==" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string32 = "WwArAF0AIABEAHUAbQBwACAAZgBpAGwAZQAgAGUAbgBjAHIAeQBwAHQAZQBkACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkALgA=" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string33 = "WwArAF0AIABMAFMAQQBTAFMAIABkAHUAbQBwACAAYwByAGUAYQB0AGUAZAAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5AC4A" nocase ascii wide
        // Description: Dumping LSASS Evaded Endpoint Security Solutions
        // Reference: https://github.com/yehia-mamdouh/Lsassx
        $string34 = "yehia-mamdouh/Lsassx" nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
