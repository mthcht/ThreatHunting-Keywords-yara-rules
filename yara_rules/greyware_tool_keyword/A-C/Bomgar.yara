rule Bomgar
{
    meta:
        description = "Detection patterns for the tool 'Bomgar' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bomgar"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string1 = /\.beyondtrustcloud\.com\/session_complete/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string2 = /\/bomgar\-rep\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string3 = /\/bomgar\-rep\-installer\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string4 = /\/bomgar\-scc\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string5 = /\/bomgar\-scc\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string6 = /\\appdata\\local\\bomgar\\bomgar\-rep\\/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string7 = /\\Bomgar\-enum_cp\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string8 = /\\bomgar\-rep\.cache\\/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string9 = /\\bomgar\-rep\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string10 = /\\bomgar\-rep\-installer\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string11 = /\\bomgar\-scc\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string12 = /\\bomgar\-scc\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string13 = /\\BOMGAR\-SCC\.EXE\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string14 = /\\cbhook\-x86\.dll/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string15 = /\\CurrentVersion\\Run\\Bomgar\sSupport\sReconnect/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string16 = /\\CurrentVersion\\Uninstall\\Representative\sConsole\s\[eval\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string17 = /\\embedhook\-x64\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string18 = /\\embedhook\-x86\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string19 = /\\programdata\\bomgar\-scc\-/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string20 = /\>Bomgar\sCorporation\<\/Data\>/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string21 = /\>Remote\sSupport\sCustomer\sClient\<\/Data\>/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string22 = /\>Representative\sConsole\<\/Data\>/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string23 = /beyondtrustcloud\.com\\Software\\Qt6/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string24 = /bomgar\-rdp\.exe/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string25 = /\'Company\'\>BeyondTrust\<\/Data\>/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string26 = /\'Company\'\>bomgar\<\/Data\>/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string27 = /eval\-.{0,1000}\.beyondtrustcloud\.com/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string28 = /license\.bomgar\.com/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string29 = /\'TaskName\'\>\\Bomgar\sTask\s/ nocase ascii wide
        // Description: Bomgar beyoundtrust Remote access software - abused by attackers
        // Reference: https://www.beyondtrust.com/
        $string30 = /To\:\sAll\sRepresentatives\s\sFrom\:\sRemote\sSupport\s.{0,1000}\shas\sadded\sa\snote\sto\sthis\ssession\./ nocase ascii wide

    condition:
        any of them
}
