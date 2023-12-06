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
        $string1 = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\s\>\scron\s\&\&\scrontab\scron/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\>\s.{0,1000}\scrontab\scron/ nocase ascii wide
        // Description: Netcat Realy on windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string3 = /echo\snc\s\-l\s\-p\s.{0,1000}\s\>\s.{0,1000}\.bat/ nocase ascii wide
        // Description: Netcat Realy on windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string4 = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s.{0,1000}\.bat/ nocase ascii wide
        // Description: Netcat Backdoor on Linux - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string5 = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: Netcat Backdoor on Windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string6 = /nc\s\-l\s\-p\s.{0,1000}\s\-e\scmd\.exe/ nocase ascii wide
        // Description: Port scanner with netcat
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string7 = /nc\s\-v\s\-n\s\-z\s\-w1\s.{0,1000}\-/ nocase ascii wide
        // Description: netcat common arguments
        // Reference: N/A
        $string8 = /nc\s\-z\s\-v\s.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}
