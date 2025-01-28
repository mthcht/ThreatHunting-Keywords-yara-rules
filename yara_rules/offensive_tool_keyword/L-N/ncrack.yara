rule ncrack
{
    meta:
        description = "Detection patterns for the tool 'ncrack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ncrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string1 = "/ncrack-"
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string2 = /\/ncrack\.git/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string3 = /ncrack\-.{0,1000}\.dmg/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string4 = /ncrack\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string5 = /ncrack\.exe/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string6 = /NcrackInstaller\.exe/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string7 = /ncrack\-master\.zip/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string8 = "ncrack-services" nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string9 = "nmap/ncrack" nocase ascii wide

    condition:
        any of them
}
