rule Sn1per
{
    meta:
        description = "Detection patterns for the tool 'Sn1per' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sn1per"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automated Pentest Recon Scanner.
        // Reference: https://github.com/1N3/Sn1per
        $string1 = /.{0,1000}1N3\/Sn1per.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
