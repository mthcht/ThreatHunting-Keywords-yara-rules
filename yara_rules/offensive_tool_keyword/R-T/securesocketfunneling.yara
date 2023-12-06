rule securesocketfunneling
{
    meta:
        description = "Detection patterns for the tool 'securesocketfunneling' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "securesocketfunneling"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Secure Socket Funneling (SSF) is a network tool and toolkit It provides simple and efficient ways to forward data from multiple sockets (TCP or UDP) through a single secure TLS link to a remote computer
        // Reference: https://securesocketfunneling.github.io/ssf/#home
        $string1 = /securesocketfunneling/ nocase ascii wide

    condition:
        any of them
}
