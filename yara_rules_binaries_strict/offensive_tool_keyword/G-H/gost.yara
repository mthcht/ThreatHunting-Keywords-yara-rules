rule gost
{
    meta:
        description = "Detection patterns for the tool 'gost' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gost"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string1 = /C\:\\Windows\\System\.exe.{0,100}\s\-L\srtcp\:\/\/0\.0\.0\.0\:8087\/127\.0\.0\.1\:4444\s\-F\ssocks5\:\/\/.{0,100}\:.{0,100}\@.{0,100}\:443/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string2 = "ginuerzh/gost" nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string3 = /gost\s\-L\=\:.{0,100}\s\-F\=.{0,100}\:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string4 = /gost\s\-L\=admin\:.{0,100}\@localhost\:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string5 = /gost\s\-L\=forward\+ssh\:\/\/\:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string6 = "gost -L=rtcp://" nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string7 = "gost -L=rudp://" nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string8 = "gost -L=ssh://:" nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string9 = "gost -L=ssu://" nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string10 = "gost -L=udp://" nocase ascii wide
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
