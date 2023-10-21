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
        $string1 = /socat\sexec:/ nocase ascii wide
        // Description: socat bind shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /socat\sFILE:.*tty.*raw.*echo\=0\sTCP.*:/ nocase ascii wide
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3 = /socat\sfile:.*tty.*raw.*echo\=0\stcp\-listen:/ nocase ascii wide
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string4 = /socat\s\-O\s\/tmp\// nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string5 = /socat\sTCP4\-LISTEN:.*\sfork\sTCP4:.*:/ nocase ascii wide
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string6 = /socat\stcp\-connect/ nocase ascii wide
        // Description: socat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string7 = /socat\stcp\-connect:.*:.*\sexec:.*bash\s\-li.*.*pty.*stderr.*setsid.*sigint.*sane/ nocase ascii wide
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string8 = /socat\stcp\-connect:.*:.*\sexec:\/bin\/sh/ nocase ascii wide
        // Description: socat bind shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9 = /socat\sTCP\-LISTEN:.*.*reuseaddr.*fork\sEXEC:\/bin\/sh/ nocase ascii wide

    condition:
        any of them
}