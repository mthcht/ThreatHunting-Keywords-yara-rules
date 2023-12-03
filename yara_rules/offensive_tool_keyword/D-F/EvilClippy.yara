rule EvilClippy
{
    meta:
        description = "Detection patterns for the tool 'EvilClippy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilClippy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string1 = /.{0,1000}\/evilclippy\.cs.{0,1000}/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string2 = /.{0,1000}\/EvilClippy\.git.{0,1000}/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string3 = /.{0,1000}\\evilclippy\.cs.{0,1000}/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string4 = /.{0,1000}_EvilClippy\..{0,1000}/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string5 = /.{0,1000}EvilClippy\.exe.{0,1000}/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string6 = /.{0,1000}EvilClippy\-master.{0,1000}/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string7 = /.{0,1000}eviloffice\.exe.{0,1000}/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string8 = /.{0,1000}outflanknl\/EvilClippy.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
