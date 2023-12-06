rule Office_DDE_Payloads
{
    meta:
        description = "Detection patterns for the tool 'Office-DDE-Payloads' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Office-DDE-Payloads"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of scripts and templates to generate Word and Excel documents embedded with the DDE. macro-less command execution technique described by @_staaldraad and @0x5A1F (blog post link in References section below). Intended for use during sanctioned red team engagements and/or phishing campaigns.
        // Reference: https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads
        $string1 = /Office\-DDE\-Payloads/ nocase ascii wide

    condition:
        any of them
}
