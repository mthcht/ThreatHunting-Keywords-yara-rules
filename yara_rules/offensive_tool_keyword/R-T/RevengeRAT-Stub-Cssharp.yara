rule RevengeRAT_Stub_Cssharp
{
    meta:
        description = "Detection patterns for the tool 'RevengeRAT-Stub-Cssharp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RevengeRAT-Stub-Cssharp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RevengeRAT - AsyncRAT  Simple RAT
        // Reference: https://github.com/NYAN-x-CAT/RevengeRAT-Stub-Cssharp
        $string1 = /052C26C0\-7979\-4555\-89CE\-34C5CE8D8B34/ nocase ascii wide
        // Description: RevengeRAT - AsyncRAT  Simple RAT
        // Reference: https://github.com/NYAN-x-CAT/RevengeRAT-Stub-Cssharp
        $string2 = /9ae37b21e20b611787f1219137b545597235c23fd54c0e73919b9ae3266bd046/ nocase ascii wide
        // Description: RevengeRAT - AsyncRAT  Simple RAT
        // Reference: https://github.com/NYAN-x-CAT/RevengeRAT-Stub-Cssharp
        $string3 = /c4f026c01e451e1afa61ab8233fd15a3c0b4da615eae5d893db82b84bbe49e40/ nocase ascii wide
        // Description: RevengeRAT - AsyncRAT  Simple RAT
        // Reference: https://github.com/NYAN-x-CAT/RevengeRAT-Stub-Cssharp
        $string4 = /RevengeRAT\-Stub\-CSsharp/ nocase ascii wide

    condition:
        any of them
}
