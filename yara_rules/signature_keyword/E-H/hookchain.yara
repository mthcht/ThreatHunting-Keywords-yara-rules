rule hookchain
{
    meta:
        description = "Detection patterns for the tool 'hookchain' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hookchain"
        rule_category = "signature_keyword"

    strings:
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string1 = /Generic\.HookChain\.A\.88E059A3/ nocase ascii wide

    condition:
        any of them
}
