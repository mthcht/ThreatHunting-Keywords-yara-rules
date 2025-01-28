rule typeperf
{
    meta:
        description = "Detection patterns for the tool 'typeperf' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "typeperf"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: checks how many processes are waiting for CPU time every 120 seconds, capturing it onc - most likely for sandbox evasion or timing mechanism
        // Reference: https://www.securonix.com/blog/threat-labs-security-advisory-new-ocxharvester-attack-campaign-leverages-modernized-more_eggs-suite/
        $string1 = /typeperf\.exe\s\\"\\System\\Processor\sQueue\sLength\\"\s\-si\s.{0,1000}\s\-sc\s1/ nocase ascii wide

    condition:
        any of them
}
