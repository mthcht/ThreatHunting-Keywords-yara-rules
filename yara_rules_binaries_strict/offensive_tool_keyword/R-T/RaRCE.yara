rule RaRCE
{
    meta:
        description = "Detection patterns for the tool 'RaRCE' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RaRCE"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string1 = " CVE-2023-38831-RaRCE" nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string2 = /\srarce\.py/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string3 = "/CVE-2023-38831-RaRCE" nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string4 = /\/rarce\.py/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string5 = /\\rarce\.py/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string6 = "from rarce import exploit" nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string7 = "pip install rarce" nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string8 = "python -m rarce " nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string9 = /rarce\s.{0,100}\.pdf\s.{0,100}\.rar/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string10 = /rarce\s.{0,100}\.rar/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string11 = /rarce\-1\.0\.0\.tar\.gz/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string12 = /rarce\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
        // Description: An easy to install and easy to run tool for generating exploit payloads for CVE-2023-38831 - WinRAR RCE before versions 6.23
        // Reference: https://github.com/ignis-sec/CVE-2023-38831-RaRCE
        $string13 = /totally\slegit\spdf\.pdf/ nocase ascii wide
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
