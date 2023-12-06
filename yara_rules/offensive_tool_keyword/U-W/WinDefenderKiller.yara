rule WinDefenderKiller
{
    meta:
        description = "Detection patterns for the tool 'WinDefenderKiller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinDefenderKiller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string1 = /\swinDefKiller\s/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string2 = /disableWinDef\.cpp/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string3 = /reverseDisableWinDef\.cpp/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string4 = /RevWinDefKiller\.exe/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string5 = /WinDefenderKiller/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string6 = /winDefKiller\.exe/ nocase ascii wide

    condition:
        any of them
}
