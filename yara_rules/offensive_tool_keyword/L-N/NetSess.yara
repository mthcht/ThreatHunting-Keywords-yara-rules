rule NetSess
{
    meta:
        description = "Detection patterns for the tool 'NetSess' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSess"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string1 = /\/NetSess\.exe/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string2 = /\/NetSess\.zip/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string3 = /\\NetSess\.exe/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string4 = /\\NetSess\.zip/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string5 = /ddeeedc8ab9ab3b90c2e36340d4674fda3b458c0afd7514735b2857f26b14c6d/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string6 = /ddeeedc8ab9ab3b90c2e36340d4674fda3b458c0afd7514735b2857f26b14c6d/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string7 = /Get\-NetSessionEnum\.ps1/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string8 = /https\:\/\/www\.joeware\.net\/downloads\/dl2\.php/ nocase ascii wide
        // Description: Command line tool to enumerate NetBIOS sessions on a specified local or remote machine. 
        // Reference: https://www.joeware.net/freetools/tools/netsess/
        $string9 = /TEMP\\ns\.exe\s/ nocase ascii wide

    condition:
        any of them
}
