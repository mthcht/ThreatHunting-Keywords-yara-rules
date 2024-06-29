rule NoodleRAT
{
    meta:
        description = "Detection patterns for the tool 'NoodleRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NoodleRAT"
        rule_category = "signature_keyword"

    strings:
        // Description: AV signature of noodlerat malware
        // Reference: https://www.trendmicro.com/en_us/research/24/f/noodle-rat-reviewing-the-new-backdoor-used-by-chinese-speaking-g.html
        $string1 = /Linux\.Cloudsnooper/ nocase ascii wide
        // Description: AV signature of noodlerat malware
        // Reference: https://www.trendmicro.com/en_us/research/24/f/noodle-rat-reviewing-the-new-backdoor-used-by-chinese-speaking-g.html
        $string2 = /Linux\.NOODLERAT/ nocase ascii wide
        // Description: AV signature of noodlerat malware
        // Reference: https://www.trendmicro.com/en_us/research/24/f/noodle-rat-reviewing-the-new-backdoor-used-by-chinese-speaking-g.html
        $string3 = /Win\.NOODLERAT/ nocase ascii wide

    condition:
        any of them
}
