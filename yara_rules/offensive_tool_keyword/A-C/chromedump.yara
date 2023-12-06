rule chromedump
{
    meta:
        description = "Detection patterns for the tool 'chromedump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromedump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string1 = /\/ChromeDump\// nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string2 = /\/dumpweb\.log/ nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string3 = /ChromeDump\.git/ nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string4 = /chromedump\.py/ nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string5 = /ChromeDump\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
