rule mshta
{
    meta:
        description = "Detection patterns for the tool 'mshta' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mshta"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: using forfiles and mshta likely to evade detection and execute malicious code. It combines file enumeration with scripting and HTML-based execution which is commonly seen in malware or sophisticated attacks
        // Reference: N/A
        $string1 = /forfiles\.exe.{0,100}\s\/p\s.{0,100}\s\/m\s.{0,100}\s\/c\s.{0,100}powershell\s\.\smshta/ nocase ascii wide
        // Description: executing from public folder
        // Reference: N/A
        $string2 = /mshta\s\\"C\:\\Users\\Public\\/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string3 = /mshta\shttp.{0,100}\.hta/ nocase ascii wide
        // Description: downloading from tinyurl
        // Reference: N/A
        $string4 = /mshta\shttps\:\/\/tinyurl\.com\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string5 = /mshta\sjavascript\:.{0,100}script\:https\:/ nocase ascii wide
        // Description: Invoking a scriptlet file hosted remotely
        // Reference: N/A
        $string6 = /mshta\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,100}\.sct.{0,100}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string7 = /mshta\svbscript\:Close\(Execute\(.{0,100}script\:https\:\/\/.{0,100}\.sct/ nocase ascii wide
        // Description: downloading from tinyurl
        // Reference: N/A
        $string8 = /mshta\.exe\shttps\:\/\/tinyurl\.com\// nocase ascii wide
        // Description: Invoking a scriptlet file hosted remotely
        // Reference: N/A
        $string9 = /mshta\.exe\sjavascript\:a\=\(GetObject\(\\"script\:http.{0,100}\.sct.{0,100}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
        // Description: executing from public folder
        // Reference: N/A
        $string10 = /mshta\.exe.{0,100}\s\\"C\:\\Users\\Public\\/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string11 = /mshta\.exe.{0,100}\shttp\:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string12 = /mshta\.exe.{0,100}\shttps\:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string13 = /mshta\.exe.{0,100}\sjavascript\:.{0,100}script\:https\:/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string14 = /mshta\.exe.{0,100}\svbscript\:Close\(Execute\(.{0,100}script\:https\:\/\/.{0,100}\.sct/ nocase ascii wide
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
