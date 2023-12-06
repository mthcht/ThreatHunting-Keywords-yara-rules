rule airpwn_ng
{
    meta:
        description = "Detection patterns for the tool 'airpwn-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "airpwn-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: We force the targets browser to do what we want
        // Reference: https://github.com/ICSec/airpwn-ng
        $string1 = /airpwn\-ng/ nocase ascii wide

    condition:
        any of them
}
