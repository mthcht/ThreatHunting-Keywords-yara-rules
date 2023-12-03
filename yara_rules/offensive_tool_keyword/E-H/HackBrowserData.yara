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
        $string1 = /.{0,1000}\sHackBrowserData/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string2 = /.{0,1000}\.exe\s\-b\s.{0,1000}\s\-p\s\'C:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User\sData\\Default\'.{0,1000}/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string3 = /.{0,1000}\.exe\s\-b\sall\s\-f\sjson\s\-\-dir\sresults\s\-cc.{0,1000}/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string4 = /.{0,1000}\/HackBrowserData.{0,1000}/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string5 = /.{0,1000}hack\-browser\-data\.exe.{0,1000}/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string6 = /.{0,1000}Reflective\-HackBrowserData.{0,1000}/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string7 = /.{0,1000}Sharp\-HackBrowserData.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
