rule CMSeek
{
    meta:
        description = "Detection patterns for the tool 'CMSeek' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CMSeek"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CMS Detection and Exploitation suite - Scan WordPress. Joomla. Drupal and 130 other CMSs.
        // Reference: https://github.com/Tuhinshubhra/CMSeek
        $string1 = /\/CMSeek/ nocase ascii wide

    condition:
        any of them
}
