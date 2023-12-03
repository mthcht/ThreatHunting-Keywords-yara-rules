rule Hunter_io
{
    meta:
        description = "Detection patterns for the tool 'Hunter.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hunter.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string1 = /.{0,1000}curl\shttps:\/\/api\.hunter\.io\/v2\/domain\-search\?domain\=.{0,1000}/ nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string2 = /.{0,1000}curl\shttps:\/\/api\.hunter\.io\/v2\/email\-finder\?domain\=.{0,1000}/ nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string3 = /.{0,1000}curl\shttps:\/\/api\.hunter\.io\/v2\/email\-verifier\?email\=.{0,1000}/ nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string4 = /.{0,1000}https:\/\/api\.hunter\.io\/.{0,1000}/ nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string5 = /.{0,1000}https:\/\/hunter\.io\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
