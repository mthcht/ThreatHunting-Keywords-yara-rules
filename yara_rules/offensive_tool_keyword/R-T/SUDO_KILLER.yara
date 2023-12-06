rule SUDO_KILLER
{
    meta:
        description = "Detection patterns for the tool 'SUDO_KILLER' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SUDO_KILLER"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: sudo exploitation #Abusing sudo #Exploiting Sudo #Linux Privilege Escalation #OSCP If you like the tool and for my personal motivation so as to develop other tools please a +1 star The tool can be used by pentesters. system admins. CTF players. students. System Auditors and trolls :).
        // Reference: https://github.com/TH3xACE/SUDO_KILLER
        $string1 = /SUDO_KILLER/ nocase ascii wide

    condition:
        any of them
}
