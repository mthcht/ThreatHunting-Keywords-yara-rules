rule mv
{
    meta:
        description = "Detection patterns for the tool 'mv' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mv"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string1 = "mv /var/log/"

    condition:
        any of them
}
