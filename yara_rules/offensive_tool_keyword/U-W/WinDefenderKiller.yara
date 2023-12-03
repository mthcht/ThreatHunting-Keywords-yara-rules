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
        $string1 = /.{0,1000}\swinDefKiller\s.{0,1000}/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string2 = /.{0,1000}disableWinDef\.cpp.{0,1000}/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string3 = /.{0,1000}reverseDisableWinDef\.cpp.{0,1000}/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string4 = /.{0,1000}RevWinDefKiller\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string5 = /.{0,1000}WinDefenderKiller.{0,1000}/ nocase ascii wide
        // Description: Windows Defender Killer | C++ Code Disabling Permanently Windows Defender using Registry Keys
        // Reference: https://github.com/S12cybersecurity/WinDefenderKiller
        $string6 = /.{0,1000}winDefKiller\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
