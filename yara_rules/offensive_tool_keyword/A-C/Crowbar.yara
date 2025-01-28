rule Crowbar
{
    meta:
        description = "Detection patterns for the tool 'Crowbar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crowbar"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Crowbar (formally known as Levye) is a brute forcing tool that can be used during penetration tests. It was developed to brute force some protocols in a different manner according to other popular brute forcing tools. As an example. while most brute forcing tools use username and password for SSH brute force. Crowbar uses SSH key(s). This allows for any private keys that have been obtained during penetration tests. to be used to attack other SSH servers.
        // Reference: https://github.com/galkan/crowbar
        $string1 = "crowbar" nocase ascii wide

    condition:
        any of them
}
