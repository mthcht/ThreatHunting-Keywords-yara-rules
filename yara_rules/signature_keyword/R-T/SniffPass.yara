rule SniffPass
{
    meta:
        description = "Detection patterns for the tool 'SniffPass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffPass"
        rule_category = "signature_keyword"

    strings:
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string1 = /PUA\:Win32\/PassShow/ nocase ascii wide

    condition:
        any of them
}
