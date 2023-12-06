rule SprayingToolkit
{
    meta:
        description = "Detection patterns for the tool 'SprayingToolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SprayingToolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string1 = /\sowa\s.{0,1000}\s\-\-user\-as\-pass\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string2 = /\/aerosol\.py/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string3 = /\/LyncSniper\.ps1/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string4 = /\/sprayers\/owa\.py/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string5 = /\/SprayingToolkit/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string6 = /\/SprayingToolkit\.git/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string7 = /atomizer\simap\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string8 = /atomizer\slync\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string9 = /atomizer\sowa\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string10 = /atomizer\.py\s\-/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string11 = /atomizer\.py\simap\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string12 = /atomizer\.py\slync\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string13 = /atomizer\.py\sowa\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string14 = /core\/sprayers\/lync\.py/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string15 = /mitmdump\s\-s\saerosol\.py/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string16 = /owa\s.{0,1000}\/autodiscover\/autodiscover\.xml.{0,1000}\s\-\-recon/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string17 = /spindrift\.py\s.{0,1000}\-\-target\s/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string18 = /spindrift\.py\s\-\-domain/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string19 = /SprayingToolkit\.git/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string20 = /SprayingToolkit\-master/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string21 = /SprayingToolkit\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
