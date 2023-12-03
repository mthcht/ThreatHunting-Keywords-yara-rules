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
        $string1 = /.{0,1000}\.exe\scompute\s\-\-sid\s.{0,1000}\s\-\-kdskey\s.{0,1000}/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string2 = /.{0,1000}\.exe\sgmsainfo\s\-\-sid\s.{0,1000}/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string3 = /.{0,1000}\.exe\skdsinfo\s\-\-guid\s.{0,1000}/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string4 = /.{0,1000}\/GoldenGMSA\.git.{0,1000}/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string5 = /.{0,1000}GoldenGMSA\.exe.{0,1000}/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string6 = /.{0,1000}GoldenGMSA\-main.{0,1000}/ nocase ascii wide
        // Description: GolenGMSA tool for working with GMSA passwords
        // Reference: https://github.com/Semperis/GoldenGMSA
        $string7 = /.{0,1000}Semperis\/GoldenGMSA.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
