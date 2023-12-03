rule evilginx2
{
    meta:
        description = "Detection patterns for the tool 'evilginx2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilginx2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string1 = /.{0,1000}evilginx\.exe.{0,1000}/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string2 = /.{0,1000}evilginx2.{0,1000}/ nocase ascii wide
        // Description: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies allowing for the bypass of 2-factor authentication
        // Reference: https://github.com/kgretzky/evilginx2
        $string3 = /.{0,1000}evilginx\-mastery.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
