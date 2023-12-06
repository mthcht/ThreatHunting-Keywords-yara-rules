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
        $string1 = /findstr\s.{0,1000}cpassword\s.{0,1000}\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2 = /findstr\s.{0,1000}vnc\.ini/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string3 = /findstr\s\/si\ssecret\s.{0,1000}\.docx/ nocase ascii wide

    condition:
        any of them
}
