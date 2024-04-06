rule whoami
{
    meta:
        description = "Detection patterns for the tool 'whoami' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whoami"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: N/A
        $string1 = /\\x2f\\x75\\x73\\x72\\x2f\\x62\\x69\\x6e\\x2f\\x77\\x68\\x6f\\x61\\x6d\\x69/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: N/A
        $string2 = /imaohw\/nib\/rsu\// nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for Lateral Movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: N/A
        $string3 = /L3Vzci9iaW4vd2hvYW1p/ nocase ascii wide

    condition:
        any of them
}
