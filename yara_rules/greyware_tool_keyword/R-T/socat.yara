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
        $string2 = /socat\sFILE\:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\sTCP.{0,1000}\:/
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /socat\sfile\:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\stcp\-listen\:/
        // Description: contains an IP address as part of a URL or network destination formatted in an unconventional but technically valid way (hexa - octal - binary)
        // Reference: https://x.com/CraigHRowland/status/1821176342999921040
        $string4 = "socat http://0x0"
        // Description: contains an IP address as part of a URL or network destination formatted in an unconventional but technically valid way (hexa - octal - binary)
        // Reference: https://x.com/CraigHRowland/status/1821176342999921040
        $string5 = /socat\s\-lp\s.{0,1000}\shttp\:\/\/0x0/
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string6 = "socat -O /tmp/"
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string7 = /socat\sTCP4\-LISTEN\:.{0,1000}\sfork\sTCP4\:.{0,1000}\:/
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string8 = "socat tcp-connect"
        // Description: socat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string9 = /socat\stcp\-connect\:.{0,1000}\:.{0,1000}\sexec\:.{0,1000}bash\s\-li.{0,1000}.{0,1000}pty.{0,1000}stderr.{0,1000}setsid.{0,1000}sigint.{0,1000}sane/
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10 = /socat\stcp\-connect\:.{0,1000}\:.{0,1000}\sexec\:\/bin\/sh/
        // Description: socat bind shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string11 = /socat\sTCP\-LISTEN\:.{0,1000}.{0,1000}reuseaddr.{0,1000}fork\sEXEC\:\/bin\/sh/

    condition:
        any of them
}
