rule WorldWind_Stealer
{
    meta:
        description = "Detection patterns for the tool 'WorldWind-Stealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WorldWind-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WorldWind Stealer This stealer sends logs directly to your telegram id from a Bot that YOU Create with telegram
        // Reference: https://github.com/Leecher21/WorldWind-Stealer
        $string1 = /WorldWind\sStealer\.zip/ nocase ascii wide
        // Description: WorldWind Stealer This stealer sends logs directly to your telegram id from a Bot that YOU Create with telegram
        // Reference: https://github.com/Leecher21/WorldWind-Stealer
        $string2 = /WorldWind\-Stealer/ nocase ascii wide

    condition:
        any of them
}
