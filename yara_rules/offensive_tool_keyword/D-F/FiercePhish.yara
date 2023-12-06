rule FiercePhish
{
    meta:
        description = "Detection patterns for the tool 'FiercePhish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FiercePhish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FiercePhish is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns. schedule sending of emails. and much more. The features will continue to be expanded and will include website spoofing. click tracking. and extensive notification options. 
        // Reference: https://github.com/Raikia/FiercePhish
        $string1 = /FiercePhish/ nocase ascii wide

    condition:
        any of them
}
