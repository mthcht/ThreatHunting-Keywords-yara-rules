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
        $string1 = /.{0,1000}\/ChromeDump\/.{0,1000}/ nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string2 = /.{0,1000}\/dumpweb\.log.{0,1000}/ nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string3 = /.{0,1000}ChromeDump\.git.{0,1000}/ nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string4 = /.{0,1000}chromedump\.py.{0,1000}/ nocase ascii wide
        // Description: ChromeDump is a small tool to dump all JavaScript and other ressources going through the browser
        // Reference: https://github.com/g4l4drim/ChromeDump
        $string5 = /.{0,1000}ChromeDump\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
