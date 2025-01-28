rule GonnaCry
{
    meta:
        description = "Detection patterns for the tool 'GonnaCry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GonnaCry"
        rule_category = "signature_keyword"

    strings:
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string1 = /Generic\.Linux\.GonnaCryRansom/
        // Description: a linux ransomware
        // Reference: https://github.com/tarcisio-marinho/GonnaCry
        $string2 = /Linux\/Filecoder\.GonnaCry/

    condition:
        any of them
}
