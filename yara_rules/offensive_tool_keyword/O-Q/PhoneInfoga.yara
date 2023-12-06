rule PhoneInfoga
{
    meta:
        description = "Detection patterns for the tool 'PhoneInfoga' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhoneInfoga"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An OSINT framework for phone numbers.
        // Reference: https://github.com/sundowndev/PhoneInfoga
        $string1 = /PhoneInfoga/ nocase ascii wide

    condition:
        any of them
}
