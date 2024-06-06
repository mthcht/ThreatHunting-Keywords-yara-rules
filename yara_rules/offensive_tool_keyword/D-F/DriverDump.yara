rule DriverDump
{
    meta:
        description = "Detection patterns for the tool 'DriverDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DriverDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\/DriverDump\.exe/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\/POC\/driverdump\// nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\\DriverDump\.c/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\\DriverDump\.exe/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\\DriverDump\.sln/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\\DriverDump\.vcxproj/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\\nanodump\.c/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /4f3632bb0c4eb05c443535dd3a773f83b3ac47f20ba75fbc3a2c8e6b80a46c60/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /5b3811e463d5b424593910cbf7fd06218e993f8399a9add27b053f98bc984587/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /7f005c1ea9c2021b5db5807fdf9e8e9f502b28f089ff17dc85b7d480a3e3d143/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /83DF0D0B\-8FC6\-4BCA\-9982\-4D26523515A2/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /c7600f446daa53037a63ad765e0873a9c45adfd8944e5fee1c1586936ecf2928/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /Data\sName\=\"ServiceName\"\>procexp\<\/Data\>/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = /L\"NanoDumpPwd\"/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = /NanoDumpPPLmedicPipe/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = /NanoDumpSSPPipe/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string17 = /pypykatz\slsa\sminidump/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string18 = /SYSTEM\\CurrentControlSet\\Services\\procexp/ nocase ascii wide
        // Description: abusing the old process explorer driver to grab a privledged handle to lsass and then dump it
        // Reference: https://github.com/trustedsec/The_Shelf
        $string19 = /The\snanodump\swas\screated\ssuccesfully/ nocase ascii wide

    condition:
        any of them
}
