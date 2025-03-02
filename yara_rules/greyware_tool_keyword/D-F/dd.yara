rule dd
{
    meta:
        description = "Detection patterns for the tool 'dd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects overwriting (effectively wiping/deleting) the file
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string1 = "dd if=/dev/nul" nocase ascii wide
        // Description: Detects overwriting (effectively wiping/deleting) the file
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string2 = "dd if=/dev/zero" nocase ascii wide
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string3 = /sudo\sdd\sif\=\/dev\/zero\sbs\=1000\scount\=5\sof\=.{0,1000}log/

    condition:
        any of them
}
