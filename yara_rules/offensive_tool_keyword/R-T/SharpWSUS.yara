rule SharpWSUS
{
    meta:
        description = "Detection patterns for the tool 'SharpWSUS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpWSUS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpWSUS is a CSharp tool for Lateral Movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string1 = /\.exe\screate\s\/payload.{0,1000}\s\/kb/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for Lateral Movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string2 = /\/SharpWSUS/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for Lateral Movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string3 = /sharpwsus\slocate/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for Lateral Movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string4 = /SharpWSUS/ nocase ascii wide
        // Description: SharpWSUS is a CSharp tool for Lateral Movement through WSUS
        // Reference: https://github.com/nettitude/SharpWSUS
        $string5 = /SharpWSUS\./ nocase ascii wide

    condition:
        any of them
}
