rule nc
{
    meta:
        description = "Detection patterns for the tool 'nc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Linux Persistence Shell cron
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /\s\/bin\/nc\s.{0,100}\s\-e\s\/bin\/bash.{0,100}\s\>\scron\s\&\&\scrontab\scron/
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /\s\/bin\/nc\s.{0,100}\s\-e\s\/bin\/bash.{0,100}\>\s.{0,100}\scrontab\scron/
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = "/nc64 -i "
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string4 = "/nc64 -lvp "
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string5 = "/nc64 -zv "
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string6 = /\\nc\.exe\s\-Ldp\s.{0,100}\s\-e\scmd\.exe/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string7 = /\\nc64\.exe\s\-i\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string8 = /\\nc64\.exe\s\-i/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string9 = /\\nc64\.exe\s\-lvp\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string10 = /\\nc64\.exe\s\-zv\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string11 = /\\nc64\.exe\\"\s\-i\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string12 = /\\nc64\.exe\\"\s\-lvp\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string13 = /\\nc64\.exe\\"\s\-zv\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string14 = /\\ncat.{0,100}\s\-e\scmd\.exe\s\-\-keep\-open/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string15 = /\\windows\\currentversion\\run\s\-v\snetcat\s/ nocase ascii wide
        // Description: Netcat Realy on windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string16 = /echo\snc\s\-l\s\-p\s.{0,100}\s\>\s.{0,100}\.bat/ nocase ascii wide
        // Description: Netcat Realy on windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string17 = /nc\s\-l\s\-p\s.{0,100}\s\-e\s.{0,100}\.bat/ nocase ascii wide
        // Description: Netcat Backdoor on Linux - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string18 = /nc\s\-l\s\-p\s.{0,100}\s\-e\s\/bin\/bash/
        // Description: Netcat Backdoor on Windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string19 = /nc\s\-l\s\-p\s.{0,100}\s\-e\scmd\.exe/ nocase ascii wide
        // Description: Port scanner with netcat
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string20 = /nc\s\-v\s\-n\s\-z\s\-w1\s.{0,100}\-/ nocase ascii wide
        // Description: netcat common arguments
        // Reference: N/A
        $string21 = /nc\s\-z\s\-v\s.{0,100}\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string22 = /nc\.exe\s.{0,100}\s\-e\scmd\.exe\\"\s\/sc\sONCE\s/ nocase ascii wide
        // Description: backdoor with netcat - used by the Ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string23 = /nc\.exe\s\-e\s\\windows\\system32\\cmd\.exe\s.{0,100}\sstart\=\sauto/ nocase ascii wide
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
