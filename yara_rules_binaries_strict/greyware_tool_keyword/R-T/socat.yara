rule socat
{
    meta:
        description = "Detection patterns for the tool 'socat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "socat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string1 = "socat exec:"
        // Description: socat bind shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /socat\sFILE\:.{0,100}tty.{0,100}raw.{0,100}echo\=0\sTCP.{0,100}\:/
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /socat\sfile\:.{0,100}tty.{0,100}raw.{0,100}echo\=0\stcp\-listen\:/
        // Description: contains an IP address as part of a URL or network destination formatted in an unconventional but technically valid way (hexa - octal - binary)
        // Reference: https://x.com/CraigHRowland/status/1821176342999921040
        $string4 = "socat http://0x0"
        // Description: contains an IP address as part of a URL or network destination formatted in an unconventional but technically valid way (hexa - octal - binary)
        // Reference: https://x.com/CraigHRowland/status/1821176342999921040
        $string5 = /socat\s\-lp\s.{0,100}\shttp\:\/\/0x0/
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string6 = "socat -O /tmp/"
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string7 = /socat\sTCP4\-LISTEN\:.{0,100}\sfork\sTCP4\:.{0,100}\:/
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string8 = "socat tcp-connect"
        // Description: socat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string9 = /socat\stcp\-connect\:.{0,100}\:.{0,100}\sexec\:.{0,100}bash\s\-li.{0,100}.{0,100}pty.{0,100}stderr.{0,100}setsid.{0,100}sigint.{0,100}sane/
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10 = /socat\stcp\-connect\:.{0,100}\:.{0,100}\sexec\:\/bin\/sh/
        // Description: socat bind shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string11 = /socat\sTCP\-LISTEN\:.{0,100}.{0,100}reuseaddr.{0,100}fork\sEXEC\:\/bin\/sh/
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
