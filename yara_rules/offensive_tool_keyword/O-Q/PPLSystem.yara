rule PPLSystem
{
    meta:
        description = "Detection patterns for the tool 'PPLSystem' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLSystem"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string1 = /\.exe\s\-\-dll\s.{0,1000}\s\-\-dump\s.{0,1000}\s\-\-pid\s/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string2 = /\/pplsystem\.exe/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string3 = /\/PPLSystem\.git/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string4 = /\[\+\]\sRemote\sCOM\ssecret\s\:\s/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string5 = /\\pplsystem\.exe/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string6 = /\\PPLSystem\-main/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string7 = /531870bd9f59ac799dfa6573472db1966cd3a9f8ece84d2f2e409e4384770b4a/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string8 = /Live\sDump\sCapture\sDump\sData\sAPI\sended\.\sNT\sStatus\:\sSTATUS_SUCCESS\./ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string9 = /pplsystem\.exe\s/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string10 = /Slowerzs\/PPLSystem/ nocase ascii wide

    condition:
        any of them
}
