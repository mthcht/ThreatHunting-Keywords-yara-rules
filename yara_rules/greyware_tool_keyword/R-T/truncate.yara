rule truncate
{
    meta:
        description = "Detection patterns for the tool 'truncate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "truncate"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string1 = "truncate -s 0 /var/log/messages"
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string2 = "truncate --size=0 /var/log/security"

    condition:
        any of them
}
