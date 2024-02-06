rule evilqr
{
    meta:
        description = "Detection patterns for the tool 'evilqr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilqr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Proof-of-concept to demonstrate dynamic QR swap phishing attacks in practice
        // Reference: https://github.com/kgretzky/evilqr
        $string1 = /\/evilqr\.git/ nocase ascii wide
        // Description: Proof-of-concept to demonstrate dynamic QR swap phishing attacks in practice
        // Reference: https://github.com/kgretzky/evilqr
        $string2 = /evilqr\-main/ nocase ascii wide
        // Description: Proof-of-concept to demonstrate dynamic QR swap phishing attacks in practice
        // Reference: https://github.com/kgretzky/evilqr
        $string3 = /evilqr\-phishing/ nocase ascii wide
        // Description: Proof-of-concept to demonstrate dynamic QR swap phishing attacks in practice
        // Reference: https://github.com/kgretzky/evilqr
        $string4 = /evilqr\-server/ nocase ascii wide
        // Description: Proof-of-concept to demonstrate dynamic QR swap phishing attacks in practice
        // Reference: https://github.com/kgretzky/evilqr
        $string5 = /http\:\/\/127\.0\.0\.1\:35000/ nocase ascii wide
        // Description: Proof-of-concept to demonstrate dynamic QR swap phishing attacks in practice
        // Reference: https://github.com/kgretzky/evilqr
        $string6 = /kgretzky\/evilqr/ nocase ascii wide

    condition:
        any of them
}
