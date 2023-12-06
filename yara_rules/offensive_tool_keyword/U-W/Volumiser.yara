rule Volumiser
{
    meta:
        description = "Detection patterns for the tool 'Volumiser' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Volumiser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string1 = /\sVolumiser\.exe\s/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string2 = /\/CCob\/Volumiser/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string3 = /\/Volumiser\.exe/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string4 = /\/Volumiser\.git/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string5 = /\/Volumiser\-maser\.zip/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string6 = /\\Volumiser\.exe/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string7 = /\\Volumiser\.sln/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string8 = /\\Volumiser\\Program\.cs/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string9 = /0DF38AD4\-60AF\-4F93\-9C7A\-7FB7BA692017/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string10 = /Volumiser\.exe\s\-\-image/ nocase ascii wide
        // Description: Volumiser is a command line tool and interactive console GUI for listing - browsing and extracting files from common virtual machine hard disk image formats.
        // Reference: https://github.com/CCob/Volumiser
        $string11 = /Volumiser\\DiscUtils\.Ebs\\EbsMappedStream/ nocase ascii wide

    condition:
        any of them
}
