rule Cr3dOv3r
{
    meta:
        description = "Detection patterns for the tool 'Cr3dOv3r' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cr3dOv3r"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Know the dangers of credential reuse attacks.
        // Reference: https://github.com/D4Vinci/Cr3dOv3r
        $string1 = /Cr3dOv3r/ nocase ascii wide

    condition:
        any of them
}
