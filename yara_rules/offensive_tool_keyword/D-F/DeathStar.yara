rule DeathStar
{
    meta:
        description = "Detection patterns for the tool 'DeathStar' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeathStar"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DeathStar is a Python script that uses Empires RESTful API to automate gaining Domain and/or Enterprise Admin rights in Active Directory environments using some of the most common offensive TTPs.
        // Reference: https://github.com/byt3bl33d3r/DeathStar
        $string1 = /github.{0,1000}\/DeathStar/ nocase ascii wide

    condition:
        any of them
}
