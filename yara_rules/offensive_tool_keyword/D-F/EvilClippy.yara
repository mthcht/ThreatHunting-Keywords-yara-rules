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
        $string1 = /\/EvilClippy\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string2 = /\/evilclippy\.cs/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string3 = /\/EvilClippy\.git/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string4 = /\\EvilClippy\-.{0,1000}\.zip/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string5 = /\\evilclippy\.cs/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string6 = /_EvilClippy\./ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string7 = /62eb5977f66221339e954ea9e4947966ad4558966264814a406b93dab8b275df/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string8 = /EvilClippy\.exe/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string9 = /EvilClippy\-master/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string10 = /eviloffice\.exe\s/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string11 = /eviloffice\.exe/ nocase ascii wide
        // Description: A cross-platform assistant for creating malicious MS Office documents
        // Reference: https://github.com/outflanknl/EvilClippy
        $string12 = /outflanknl\/EvilClippy/ nocase ascii wide

    condition:
        any of them
}
