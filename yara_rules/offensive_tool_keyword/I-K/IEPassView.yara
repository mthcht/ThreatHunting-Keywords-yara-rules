rule IEPassView
{
    meta:
        description = "Detection patterns for the tool 'IEPassView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IEPassView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string1 = /\/iepv\.exe/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string2 = /\/toolsdownload\/iepv\.zip/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string3 = /\\iepv\.cfg/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string4 = /\\iepv\.exe/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string5 = /\\IEPV\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string6 = /\\iepv\.zip\.lnk/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string7 = /_iepv\.zip\./ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string8 = /\>IE\sPass\sView\</ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string9 = /\>IE\sPasswords\sViewer\</ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string10 = /70aaf2b367b97fa35d599a6db4d08875206ef18c99d8c8c5b5f25e4f5509931a/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string11 = /Description\'\>IE\sPasswords\sViewer/ nocase ascii wide
        // Description: IE PassView scans all Internet Explorer passwords in your system and display them on the main window.
        // Reference: https://www.nirsoft.net/utils/internet_explorer_password.html
        $string12 = /iepv\.exe\s\/stext\s/ nocase ascii wide

    condition:
        any of them
}
