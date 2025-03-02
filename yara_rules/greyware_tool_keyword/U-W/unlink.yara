rule unlink
{
    meta:
        description = "Detection patterns for the tool 'unlink' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unlink"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string1 = "unlink /var/log/"
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string2 = /unlink\s\~\/\.bash_history/ nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string3 = /unlink\s\~\/\.zsh_history/ nocase ascii wide
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string4 = "unlink -f /var/log/"
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string5 = "unlink -r /var/log/"
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string6 = "unlink -rf /var/log/"

    condition:
        any of them
}
