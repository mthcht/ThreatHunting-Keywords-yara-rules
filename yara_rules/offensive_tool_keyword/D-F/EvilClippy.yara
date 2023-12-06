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
        $string1 = /\/evilclippy\.cs/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string2 = /\/EvilClippy\.git/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string3 = /\\evilclippy\.cs/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string4 = /_EvilClippy\./ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string5 = /EvilClippy\.exe/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string6 = /EvilClippy\-master/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string7 = /eviloffice\.exe/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string8 = /outflanknl\/EvilClippy/ nocase ascii wide

    condition:
        any of them
}
