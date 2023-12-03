rule peCloak
{
    meta:
        description = "Detection patterns for the tool 'peCloak' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "peCloak"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: peCloak.py (beta) - A Multi-Pass Encoder & Heuristic Sandbox Bypass AV Evasion Tool
        // Reference: https://github.com/v-p-b/peCloakCapstone/blob/master/peCloak.py
        $string1 = /.{0,1000}peCloak.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
