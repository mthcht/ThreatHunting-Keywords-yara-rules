rule Netexec
{
    meta:
        description = "Detection patterns for the tool 'Netexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Netexec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string1 = /C\:\\Windows\\Temp\\[a-zA-Z0-9]{8}.tmp/ nocase ascii wide

    condition:
        any of them
}
