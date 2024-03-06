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
        $string1 = /\skeepass\sbackdoor\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string2 = /\sKeepass\spersistence\sbackdoor\s/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string3 = /\s\-t\sschtaskbackdoor\s/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string4 = /\.exe\s\-t\skeepass\s\-f\s/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string5 = /\.exe\s\-t\sstartupfolder\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-f/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string6 = /\.exe\s\-t\stortoisesvn\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-m/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string7 = /\\SchTaskBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string8 = /\\SharPersist\\/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string9 = /9D1B853E\-58F1\-4BA5\-AEFC\-5C221CA30E48/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string10 = /9D1B853E\-58F1\-4BA5\-AEFC\-5C221CA30E48/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string11 = /c\:\\123\.txt/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string12 = /KeePass\sconfig\sfile\sis\sbackdoored\salready/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string13 = /KeePassBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string14 = /mandiant\/SharPersist/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string15 = /SchTaskBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string16 = /SharPersist/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string17 = /SharPersist\.exe/ nocase ascii wide

    condition:
        any of them
}
