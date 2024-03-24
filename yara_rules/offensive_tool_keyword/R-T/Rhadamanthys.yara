rule Rhadamanthys
{
    meta:
        description = "Detection patterns for the tool 'Rhadamanthys' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rhadamanthys"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string1 = /\sXworm\sv/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string2 = /\/XWorm\.exe/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string3 = /\/XWorm\.rar/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string4 = /\\XKlog\.txt/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string5 = /\\XWorm\.config/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string6 = /\\XWorm\.exe/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string7 = /\\XWorm\.rar/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string8 = /9950788284df125c7359aeb91435ed24d59359fac6a74ed73774ca31561cc7ae/ nocase ascii wide
        // Description: Fake Xworm - Rhadamanthys infostealer
        // Reference: https://github.com/koyaxZ/XWorm-v5-Remote-Access-Tool
        $string9 = /XWorm\-v5\-Remote\-Access\-Tool/ nocase ascii wide

    condition:
        any of them
}
