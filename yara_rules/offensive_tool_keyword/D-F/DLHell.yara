rule DLHell
{
    meta:
        description = "Detection patterns for the tool 'DLHell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLHell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string1 = /\sDLHell\.py/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string2 = /\#\#\sDLHell\sMain\sfunction/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string3 = /\#Dumps\sexported\sfunction\sfrom\slegit\sDLL\susing\swinedump/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string4 = /\#Removes\sprevious\shijacked\sdll/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string5 = /\.py\s\s\-t\s.{0,1000}\.tpe\s\-c\s.{0,1000}\.exe.{0,1000}\s\-remote\-lib\s.{0,1000}\-remote\-target\s/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string6 = /\.py\s\-t\stemplate\.tpe\s\-c\s\'calc\.exe\'/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string7 = /\/DLHell\.git/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string8 = /\/DLHell\.py/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string9 = /\\DLHell\.py/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string10 = /\\DLHell\-main\\/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string11 = /Available\sProgIDs\sand\sCLSIDs\sfor\sDLL\sHijacking\:/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string12 = /DLHell\sv2\.0/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string13 = /DLHell\.py\s\-/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string14 = /DLL\sHell\s\-\sDLL\sProxifier\/Hijacker/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string15 = /dump_exported_functions\(library\,dll_orig\)/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string16 = /f47ae40fa2ba9ad689d59f8b755ea68e116c3dd603d6f985a7eff273ce0f381b/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string17 = /impacket\.dcerpc\.v5/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string18 = /impacket\.smbconnection/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string19 = /kevin\.tellier\@synacktiv\.com/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string20 = /synacktiv\/DLHell/ nocase ascii wide

    condition:
        any of them
}
