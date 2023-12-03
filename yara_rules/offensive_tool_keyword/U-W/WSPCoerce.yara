rule WSPCoerce
{
    meta:
        description = "Detection patterns for the tool 'WSPCoerce' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSPCoerce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string1 = /.{0,1000}\sWSPCoerce\.cs.{0,1000}/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string2 = /.{0,1000}\/WSPCoerce\.git.{0,1000}/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string3 = /.{0,1000}\\WSPCoerce\.cs.{0,1000}/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string4 = /.{0,1000}slemire\/WSPCoerce.{0,1000}/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string5 = /.{0,1000}WSPCoerce\.ex.{0,1000}/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string6 = /.{0,1000}WSPCoerce\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
