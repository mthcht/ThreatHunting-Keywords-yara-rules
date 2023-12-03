rule wetransfer
{
    meta:
        description = "Detection patterns for the tool 'wetransfer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wetransfer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: WeTransfer is a popular file sharing service often used by malicious actors for phishing campaigns due to its legitimate reputation and widespread use even within some enterprises to share files
        // Reference: https://twitter.com/mthcht/status/1658853848323182597
        $string1 = /.{0,1000}https:\/\/we\.tl\/t\-.{0,1000}/ nocase ascii wide
        // Description: WeTransfer is a popular file-sharing service often used by malicious actors for phishing campaigns due to its legitimate reputation and widespread use even within some enterprises to share files
        // Reference: https://twitter.com/mthcht/status/1658853848323182597
        $string2 = /.{0,1000}https:\/\/wetransfer\.com\/api\/v4\/transfers\/.{0,1000}/ nocase ascii wide
        // Description: WeTransfer is a popular file-sharing service often used by malicious actors for phishing campaigns due to its legitimate reputation and widespread use even within some enterprises to share files
        // Reference: https://twitter.com/mthcht/status/1658853848323182597
        $string3 = /.{0,1000}https:\/\/wetransfer\.com\/downloads\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
