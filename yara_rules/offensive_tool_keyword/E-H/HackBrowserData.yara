rule HackBrowserData
{
    meta:
        description = "Detection patterns for the tool 'HackBrowserData' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HackBrowserData"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string1 = /\sHackBrowserData/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string2 = /\.exe\s\-b\s.{0,1000}\s\-p\s\'C:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User\sData\\Default\'/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string3 = /\.exe\s\-b\sall\s\-f\sjson\s\-\-dir\sresults\s\-cc/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string4 = /\/HackBrowserData/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string5 = /hack\-browser\-data\.exe/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string6 = /Reflective\-HackBrowserData/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string7 = /Sharp\-HackBrowserData/ nocase ascii wide

    condition:
        any of them
}
