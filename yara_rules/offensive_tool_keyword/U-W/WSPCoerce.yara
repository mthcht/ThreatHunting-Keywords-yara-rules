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
        $string1 = /\sWSPCoerce\.cs/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string2 = /\/WSPCoerce\.git/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string3 = /\\WSPCoerce\.cs/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string4 = /slemire\/WSPCoerce/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string5 = /WSPCoerce\.ex/ nocase ascii wide
        // Description: PoC to coerce authentication from Windows hosts using MS-WSP
        // Reference: https://github.com/slemire/WSPCoerce
        $string6 = /WSPCoerce\-main/ nocase ascii wide

    condition:
        any of them
}
