rule sqli_labs
{
    meta:
        description = "Detection patterns for the tool 'sqli-labs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sqli-labs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SQLI-LABS is a platform to learn SQLI Following labs are covered for GET and POST scenarios:
        // Reference: https://github.com/Audi-1/sqli-labs
        $string1 = /.{0,1000}Sqli\-lab.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
