rule Invoke_ProcessScan
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ProcessScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ProcessScan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script uses a list from the Equation Group leak from the shadow brokers to provide context to executeables that are running on a system.
        // Reference: https://github.com/vysecurity/Invoke-ProcessScan
        $string1 = /Invoke\-ProcessScan/ nocase ascii wide

    condition:
        any of them
}
