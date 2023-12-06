rule UsoDllLoader
{
    meta:
        description = "Detection patterns for the tool 'UsoDllLoader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UsoDllLoader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This PoC shows a technique that can be used to weaponize privileged file write vulnerabilities on Windows. It provides an alternative to the DiagHub DLL loading exploit 
        // Reference: https://github.com/itm4n/UsoDllLoader
        $string1 = /2D863D7A\-A369\-419C\-B4B3\-54BDB88B5816/ nocase ascii wide
        // Description: This PoC shows a technique that can be used to weaponize privileged file write vulnerabilities on Windows. It provides an alternative to the DiagHub DLL loading exploit 
        // Reference: https://github.com/itm4n/UsoDllLoader
        $string2 = /tcpClient\.connectTCP\(.{0,1000}127\.0\.0\.1.{0,1000}1337/ nocase ascii wide
        // Description: This PoC shows a technique that can be used to weaponize privileged file write vulnerabilities on Windows. It provides an alternative to the DiagHub DLL loading exploit 
        // Reference: https://github.com/itm4n/UsoDllLoader
        $string3 = /UsoDllLoader/ nocase ascii wide

    condition:
        any of them
}
