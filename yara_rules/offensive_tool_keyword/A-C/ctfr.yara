rule ctfr
{
    meta:
        description = "Detection patterns for the tool 'ctfr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ctfr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Abusing Certificate Transparency logs for getting HTTPS websites subdomains.
        // Reference: https://github.com/UnaPibaGeek/ctfr
        $string1 = /.{0,1000}ctfr\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
