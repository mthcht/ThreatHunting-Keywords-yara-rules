rule rattler
{
    meta:
        description = "Detection patterns for the tool 'rattler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rattler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string1 = /\sRattler\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string2 = /\sRattler_32\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string3 = /\sRattler_x64\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string4 = /\/download\/v1\.0\/payload\.dll/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string5 = /\/rattler\.git/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string6 = /\/Rattler_32\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string7 = /\/Rattler_x64\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string8 = /\\rattler\.cpp/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string9 = /\\Rattler\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string10 = /\\Rattler_32\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string11 = /\\Rattler_x64\.exe/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string12 = /\\rattler\-master/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string13 = /\]\sINFO\:\sDLL\sIS\sVULNERABLE\sTO\sDOWNLOADS\sINSTALLER\sTEST\-/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string14 = /\]\sINFO\:\sDLL\sIS\sVULNERABLE\sTO\sEXECUTABLE\sTEST/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string15 = /\]\sTARGET\sDLL\sIS\sNOT\sVULNERABLE\sTO\s/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string16 = /0de61f6d712f44fd8337794c3d933d3e0de24bae9235383904541997c604b47a/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string17 = /2d00a5df9000f49c0b42ca0fe316103af9cc3bdf11bea4da5255690193d3ef21/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string18 = /3df5882d88914a064cbba240e1b3615c69c432f807f949a80d0d4b5a9f44ef77/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string19 = /cea27c53085b6cf1d9505957144aa23b794550da5746e6a38a212a03b505e157/ nocase ascii wide
        // Description: Automated DLL Enumerator
        // Reference: https://github.com/sensepost/rattler
        $string20 = /sensepost\/rattler/ nocase ascii wide

    condition:
        any of them
}
