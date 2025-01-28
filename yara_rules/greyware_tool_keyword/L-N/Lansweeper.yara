rule Lansweeper
{
    meta:
        description = "Detection patterns for the tool 'Lansweeper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lansweeper"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string1 = /\/LansweeperSetup_.{0,1000}\.exe/ nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string2 = /\\AppData\\Local\\Temp\\lansweeper\-/ nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string3 = /\\LansweeperService\.exe/ nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string4 = /\\LansweeperSetup_.{0,1000}\.exe/ nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string5 = /\\Program\sFiles\s\(x86\)\\Lansweeper/ nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string6 = ">Lansweeper Setup<" nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string7 = ">Lansweeper<" nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string8 = /https\:\/\/update\.lansweeper\.com\/installation\.aspx/ nocase ascii wide
        // Description: Lansweeper discovers and inventories IT assets - gathering system - software and user data - abused by attackers
        // Reference: https://www.lansweeper.com/
        $string9 = /https\:\/\/www\.lansweeper\.com\/installation\.aspx/ nocase ascii wide

    condition:
        any of them
}
