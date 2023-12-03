rule SharpWSUS
{
    meta:
        description = "Detection patterns for the tool 'SharpWSUS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpWSUS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpWSUS is a CSharp tool for lateral movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string1 = /.{0,1000}\.exe\screate\s\/payload.{0,1000}\s\/kb.{0,1000}/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for lateral movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string2 = /.{0,1000}\/SharpWSUS.{0,1000}/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for lateral movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string3 = /.{0,1000}sharpwsus\slocate.{0,1000}/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for lateral movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string4 = /.{0,1000}SharpWSUS.{0,1000}/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for lateral movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string5 = /.{0,1000}SharpWSUS\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
