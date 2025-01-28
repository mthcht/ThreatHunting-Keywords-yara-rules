rule gsecdump
{
    meta:
        description = "Detection patterns for the tool 'gsecdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsecdump"
        rule_category = "signature_keyword"

    strings:
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string1 = "Adware/Gsecdump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string2 = /Hacktool\.Gsecdump/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string3 = "HackTool/Gsecdump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string4 = "HackTool:Win32/Gsecdump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string5 = "HTool-GSECDump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string6 = /PSWTool\.Win64\.Gsecdmp/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string7 = /Win32\/PSWTool\.Gsecdump/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string8 = "Win32:Gsecdump" nocase ascii wide
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
