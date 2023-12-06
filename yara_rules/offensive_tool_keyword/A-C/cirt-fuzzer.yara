rule cirt_fuzzer
{
    meta:
        description = "Detection patterns for the tool 'cirt-fuzzer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cirt-fuzzer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple TCP/UDP protocol fuzzer.
        // Reference: https://www.ecrimelabs.com/
        $string1 = /cirt\-fuzzer/ nocase ascii wide

    condition:
        any of them
}
