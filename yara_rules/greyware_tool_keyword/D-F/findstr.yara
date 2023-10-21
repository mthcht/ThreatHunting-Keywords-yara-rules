rule findstr
{
    meta:
        description = "Detection patterns for the tool 'findstr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findstr"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - gpp finder
        // Reference: N/A
        $string1 = /findstr\s.*cpassword\s.*\\sysvol\\.*\.xml/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /findstr\s.*vnc\.ini/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string3 = /findstr\s\/si\ssecret\s.*\.docx/ nocase ascii wide

    condition:
        any of them
}