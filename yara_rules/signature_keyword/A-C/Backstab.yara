rule Backstab
{
    meta:
        description = "Detection patterns for the tool 'Backstab' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Backstab"
        rule_category = "signature_keyword"

    strings:
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string1 = "VirTool:Win64/Backstab" nocase ascii wide

    condition:
        any of them
}
