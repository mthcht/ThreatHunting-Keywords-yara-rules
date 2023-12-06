rule RedHunt_OS
{
    meta:
        description = "Detection patterns for the tool 'RedHunt-OS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedHunt-OS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Virtual Machine for Adversary Emulation and Threat Hunting by RedHunt Labs RedHunt OS aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attackers arsenal as well as defenders toolkit to actively identify the threats in your environment
        // Reference: https://github.com/redhuntlabs/RedHunt-OS
        $string1 = /RedHunt\-OS/ nocase ascii wide

    condition:
        any of them
}
