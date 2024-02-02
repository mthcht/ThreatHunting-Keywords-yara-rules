rule Drupwn
{
    meta:
        description = "Detection patterns for the tool 'Drupwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Drupwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Drupal Security Scanner to perform enumerations on Drupal-based web applications.
        // Reference: https://github.com/immunIT/drupwn
        $string1 = /\/Drupwn/ nocase ascii wide

    condition:
        any of them
}
