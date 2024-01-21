rule SharpEventPersist
{
    meta:
        description = "Detection patterns for the tool 'SharpEventPersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEventPersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string1 = /\/SharpEventPersist\.git/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string2 = /27F85701\-FD37\-4D18\-A107\-20E914F8E779/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string3 = /7B4D3810\-4A77\-44A1\-8546\-779ACF02D083/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string4 = /\-file\s.{0,1000}\.bin\s\-instanceid\s1337\s\-\ssource\spersistence/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string5 = /improsec\/SharpEventPersist/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string6 = /SharpEventLoader/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string7 = /SharpEventLoader\.exe/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string8 = /SharpEventPersist/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string9 = /SharpEventPersist\.exe/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string10 = /SharpEventPersist\-main/ nocase ascii wide
        // Description: Persistence by writing/reading shellcode from Event Log
        // Reference: https://github.com/improsec/SharpEventPersist
        $string11 = /Specify\s\-instanceid\s1337.{0,1000}Specify\s\-source\s\'Persistence/ nocase ascii wide

    condition:
        any of them
}
