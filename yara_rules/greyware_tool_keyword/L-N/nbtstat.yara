rule nbtstat
{
    meta:
        description = "Detection patterns for the tool 'nbtstat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nbtstat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Displays the NetBIOS name table of the local computer. The status of registered indicates that the name is registered either by broadcast or with a WINS server.
        // Reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nbtstat
        $string1 = "nbtstat -n" nocase ascii wide

    condition:
        any of them
}
