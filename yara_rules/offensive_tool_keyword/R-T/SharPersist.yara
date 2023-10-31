rule SharPersist
{
    meta:
        description = "Detection patterns for the tool 'SharPersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharPersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string1 = /\s\-t\sschtaskbackdoor\s/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string2 = /\.exe\s\-t\skeepass\s\-f\s/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string3 = /\.exe\s\-t\sstartupfolder\s\-c\s.*\s\-a\s.*\s\-f/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string4 = /\.exe\s\-t\stortoisesvn\s\-c\s.*\s\-a\s.*\s\-m/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string5 = /9D1B853E\-58F1\-4BA5\-AEFC\-5C221CA30E48/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string6 = /KeePassBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string7 = /SchTaskBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string8 = /SharPersist/ nocase ascii wide

    condition:
        any of them
}