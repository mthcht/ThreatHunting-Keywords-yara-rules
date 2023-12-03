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
        $string1 = /.{0,1000}\sowa\s.{0,1000}\s\-\-user\-as\-pass\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string2 = /.{0,1000}\/aerosol\.py.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string3 = /.{0,1000}\/LyncSniper\.ps1.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string4 = /.{0,1000}\/sprayers\/owa\.py.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string5 = /.{0,1000}\/SprayingToolkit.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string6 = /.{0,1000}\/SprayingToolkit\.git.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string7 = /.{0,1000}atomizer\simap\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string8 = /.{0,1000}atomizer\slync\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string9 = /.{0,1000}atomizer\sowa\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string10 = /.{0,1000}atomizer\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string11 = /.{0,1000}atomizer\.py\simap\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string12 = /.{0,1000}atomizer\.py\slync\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string13 = /.{0,1000}atomizer\.py\sowa\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string14 = /.{0,1000}core\/sprayers\/lync\.py.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string15 = /.{0,1000}mitmdump\s\-s\saerosol\.py.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string16 = /.{0,1000}owa\s.{0,1000}\/autodiscover\/autodiscover\.xml.{0,1000}\s\-\-recon.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string17 = /.{0,1000}spindrift\.py\s.{0,1000}\-\-target\s.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string18 = /.{0,1000}spindrift\.py\s\-\-domain.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string19 = /.{0,1000}SprayingToolkit\.git.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string20 = /.{0,1000}SprayingToolkit\-master.{0,1000}/ nocase ascii wide
        // Description: Scripts to make password spraying attacks against Lync/S4B. OWA & O365 a lot quicker. less painful and more efficient
        // Reference: https://github.com/byt3bl33d3r/SprayingToolkit
        $string21 = /.{0,1000}SprayingToolkit\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
