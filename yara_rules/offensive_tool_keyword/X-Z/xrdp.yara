rule xrdp
{
    meta:
        description = "Detection patterns for the tool 'xrdp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xrdp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: xrdp provides a graphical login to remote machines using Microsoft Remote Desktop Protocol (RDP). xrdp accepts connections from a variety of RDP clients: FreeRDP. rdesktop. NeutrinoRDP and Microsoft Remote Desktop Client (for Windows. Mac OS. iOS and Android).can be used by attacker
        // Reference: https://github.com/neutrinolabs/xrdp
        $string1 = /xrdp\.c/ nocase ascii wide

    condition:
        any of them
}
