rule myftp_org
{
    meta:
        description = "Detection patterns for the tool 'myftp.org' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "myftp.org"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dyndns - lots of subdomains associated with malwares - myftp.org could be used in various ways for both legitimate and malicious activities (malicious mostly)
        // Reference: https://github.com/pan-unit42/iocs/blob/master/rat_nest/iocs.csv
        $string1 = /\.myftp\.org/ nocase ascii wide

    condition:
        any of them
}
