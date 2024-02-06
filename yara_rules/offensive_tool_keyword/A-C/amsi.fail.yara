rule amsi_fail
{
    meta:
        description = "Detection patterns for the tool 'amsi.fail' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "amsi.fail"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AMSI.fail generates obfuscated PowerShell snippets that break or disable AMSI for the current process. The snippets are randomly selected from a small pool of techniques/variations before being obfuscated. Every snippet is obfuscated at runtime/request so that no generated output share the same signatures.
        // Reference: https://amsi.fail/
        $string1 = /https\:\/\/amsi\.fail\// nocase ascii wide

    condition:
        any of them
}
