rule plink
{
    meta:
        description = "Detection patterns for the tool 'plink' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "plink"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: creates an SSH tunnel from the local machine to the remote machine allowing the user to connect to an RDP session on the remote machine through port 3389. This plink usage is often used by attackers
        // Reference: N/A
        $string1 = /plink\s\-N\s\-L\s.{0,1000}\:localhost\:3389\s/ nocase ascii wide

    condition:
        any of them
}
