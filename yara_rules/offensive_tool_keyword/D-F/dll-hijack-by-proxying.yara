rule dll_hijack_by_proxying
{
    meta:
        description = "Detection patterns for the tool 'dll-hijack-by-proxying' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dll-hijack-by-proxying"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string1 = /\/\/\sMalicious\spayload\sshould\sbe\simplemented\shere/ nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string2 = /\/dll\-hijack\-by\-proxying\.git/ nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string3 = /\\dll\-hijack\-by\-proxying/ nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string4 = /\\dll\-hijack\-by\-proxying\-master/ nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string5 = /tothi\/dll\-hijack\-by\-proxying/ nocase ascii wide

    condition:
        any of them
}
