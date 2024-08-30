rule genHTA
{
    meta:
        description = "Detection patterns for the tool 'genHTA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "genHTA"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generates anti-sandbox analysis HTA files without payloads. anti-sandbox analysis HTA File Generator
        // Reference: https://github.com/mdsecactivebreach/genHTA
        $string1 = /\/genHTA/ nocase ascii wide

    condition:
        any of them
}
