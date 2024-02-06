rule OMG_Credz_Plz
{
    meta:
        description = "Detection patterns for the tool 'OMG-Credz-Plz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OMG-Credz-Plz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A script used to prompt the target to enter their creds to later be exfiltrated with dropbox.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string1 = /Credz\-Plz\.ps1/ nocase ascii wide
        // Description: A script used to prompt the target to enter their creds to later be exfiltrated with dropbox.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string2 = /Credz\-Plz\-Execute\.txt/ nocase ascii wide
        // Description: A script used to prompt the target to enter their creds to later be exfiltrated with dropbox.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string3 = /Invoke\-RestMethod\s\-Uri\shttps\:\/\/content\.dropboxapi\.com\/2\/files\/upload\s\-Method\sPost\s\s\-InFile\s.{0,1000}\s\s\-Headers\s/ nocase ascii wide
        // Description: A script used to prompt the target to enter their creds to later be exfiltrated with dropbox.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string4 = /\-OMG\-Credz\-Plz/ nocase ascii wide

    condition:
        any of them
}
