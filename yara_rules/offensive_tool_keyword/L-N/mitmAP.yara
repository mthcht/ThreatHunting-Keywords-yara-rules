rule mitmAP
{
    meta:
        description = "Detection patterns for the tool 'mitmAP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmAP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A python program to create a fake AP and sniff data
        // Reference: https://github.com/xdavidhu/mitmAP
        $string1 = /\/mitmAP/ nocase ascii wide

    condition:
        any of them
}
