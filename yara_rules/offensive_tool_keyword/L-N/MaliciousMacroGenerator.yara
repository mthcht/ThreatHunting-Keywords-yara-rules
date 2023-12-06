rule MaliciousMacroGenerator
{
    meta:
        description = "Detection patterns for the tool 'MaliciousMacroGenerator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaliciousMacroGenerator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple utility design to generate obfuscated macro that also include a AV / Sandboxes escape mechanism.
        // Reference: https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator
        $string1 = /MaliciousMacroGenerator/ nocase ascii wide

    condition:
        any of them
}
