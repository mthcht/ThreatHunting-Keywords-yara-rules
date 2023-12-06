rule GoldenGMSA
{
    meta:
        description = "Detection patterns for the tool 'GoldenGMSA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoldenGMSA"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string1 = /\.exe\scompute\s\-\-sid\s.{0,1000}\s\-\-kdskey\s/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string2 = /\.exe\sgmsainfo\s\-\-sid\s/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string3 = /\.exe\skdsinfo\s\-\-guid\s/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string4 = /\/GoldenGMSA\.git/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string5 = /GoldenGMSA\.exe/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string6 = /GoldenGMSA\-main/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string7 = /Semperis\/GoldenGMSA/ nocase ascii wide

    condition:
        any of them
}
