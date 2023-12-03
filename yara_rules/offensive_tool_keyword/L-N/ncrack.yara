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
        $string1 = /.{0,1000}\/ncrack\-.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string2 = /.{0,1000}\/ncrack\.git.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string3 = /.{0,1000}ncrack\-.{0,1000}\.dmg.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string4 = /.{0,1000}ncrack\-.{0,1000}\-setup\.exe.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string5 = /.{0,1000}ncrack\.exe.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string6 = /.{0,1000}NcrackInstaller\.exe.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string7 = /.{0,1000}ncrack\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string8 = /.{0,1000}ncrack\-services.{0,1000}/ nocase ascii wide
        // Description: High-speed network authentication cracking tool.
        // Reference: https://github.com/nmap/ncrack
        $string9 = /.{0,1000}nmap\/ncrack.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
