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
        $string7 = /\/SharPersist\.git/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string8 = /\\SchTaskBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string9 = /\\SharPersist\\/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string10 = /\\TortoiseSVNHookScripts\.cs/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string11 = /7806b81514ecc44219a6f6193b15b23aea0a947f3c91b339332bea1445745596/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string12 = /9D1B853E\-58F1\-4BA5\-AEFC\-5C221CA30E48/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string13 = /c\:\\123\.txt/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string14 = /e9711f47cf9171f79bf34b342279f6fd9275c8ae65f3eb2c6ebb0b8432ea14f8/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string15 = /INFO\:\sAdding\skeepass\sbackdoor\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string16 = /INFO\:\sAdding\sregistry\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string17 = /INFO\:\sAdding\sscheduled\stask\sbackdoor\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string18 = /INFO\:\sAdding\sscheduled\stask\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string19 = /INFO\:\sAdding\sservice\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string20 = /INFO\:\sAdding\sstartup\sfolder\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string21 = /INFO\:\sAdding\stortoise\ssvn\spersistence/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string22 = /INFO\:\sChecking\sbackdoor\spresent\sin\sKeePass\sconfig\sfile/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string23 = /INFO\:\sListing\sall\sscheduled\stasks\savailable\sto\sbackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string24 = /KeePass\sconfig\sfile\sis\sbackdoored\salready/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string25 = /KeePassBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string26 = /mandiant\/SharPersist/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string27 = /SchTaskBackdoor\./ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string28 = /SharPersist\s\-/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string29 = /SharPersist/ nocase ascii wide
        // Description: SharPersist Windows persistence toolkit written in C#.
        // Reference: https://github.com/fireeye/SharPersist
        $string30 = /SharPersist\.exe/ nocase ascii wide

    condition:
        any of them
}
