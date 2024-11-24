rule PPLFault
{
    meta:
        description = "Detection patterns for the tool 'PPLFault' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLFault"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string1 = "/DumpShellcode/" nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string2 = /\/Nofault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string3 = "/PPLFault/" nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string4 = /\\GodFault\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string5 = /\\Nofault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string6 = /\\PPLFault/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string7 = /DumpShellcode\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string8 = /DumpShellcode\\/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string9 = /EventAggregation\.dll\.bak/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string10 = /EventAggregation\.dll\.patched/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string11 = /EventAggregationPH\.dll/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string12 = "gabriellandau/PPLFault" nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string13 = "GMShellcode" nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string14 = /GMShellcode\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string15 = /GMShellcode\\/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string16 = /GodFault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string17 = /GodFault\\GodFault/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string18 = "HIJACK_DLL_PATH" nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string19 = /lsass\.dmp/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string20 = /NoFault\\NoFault\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string21 = /PPLFault\./ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string22 = /PPLFault\.exe/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string23 = /PPLFault\-Localhost\-SMB\.ps1/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string24 = /PPLFaultPayload\.dll/ nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string25 = "PPLFaultTemp" nocase ascii wide
        // Description: Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.
        // Reference: https://github.com/gabriellandau/PPLFault
        $string26 = /smbserver\.py\s\-payload/ nocase ascii wide
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
