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
        $string1 = /.{0,1000}\s\-t\sschtaskbackdoor\s.{0,1000}/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string2 = /.{0,1000}\.exe\s\-t\skeepass\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string3 = /.{0,1000}\.exe\s\-t\sstartupfolder\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-f.{0,1000}/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string4 = /.{0,1000}\.exe\s\-t\stortoisesvn\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-m.{0,1000}/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string5 = /.{0,1000}9D1B853E\-58F1\-4BA5\-AEFC\-5C221CA30E48.{0,1000}/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string6 = /.{0,1000}KeePassBackdoor\..{0,1000}/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string7 = /.{0,1000}SchTaskBackdoor\..{0,1000}/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string8 = /.{0,1000}SharPersist.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
