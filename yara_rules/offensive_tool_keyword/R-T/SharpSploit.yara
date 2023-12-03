rule SharpSploit
{
    meta:
        description = "Detection patterns for the tool 'SharpSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpSploitis a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
        // Reference: https://github.com/cobbr/SharpSploit
        $string1 = /.{0,1000}SharpSploit.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
