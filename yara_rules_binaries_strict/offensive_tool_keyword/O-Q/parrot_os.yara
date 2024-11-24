rule parrot_os
{
    meta:
        description = "Detection patterns for the tool 'parrot os' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "parrot os"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string1 = " parrot main " nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string2 = /\sparrot\.run\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string3 = " parrot-backports " nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string4 = " parrot-security " nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string5 = /\/deb\.parrot\.sh\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string6 = /\/parrot\/iso\/.{0,100}\.iso/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string7 = "/parrot-mirror/" nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string8 = "/parrot-on-docker/" nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string9 = "/parrotsec/" nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string10 = /bunny\.deb\.parrot\.sh\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string11 = /edge1\.parrot\.run/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string12 = /mirrors\.aliyun\.com\/parrot/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string13 = /parrot.{0,100}security\.vdi/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string14 = /parrotsec\.org\/download\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string15 = /Parrot\-security\-.{0,100}\.iso/ nocase ascii wide
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
