rule jwt_tool
{
    meta:
        description = "Detection patterns for the tool 'jwt_tool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jwt_tool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: jwt_tool.py is a toolkit for validating. forging. scanning and tampering JWTs (JSON Web Tokens).
        // Reference: https://github.com/ticarpi/jwt_tool
        $string1 = /jwt_tool/ nocase ascii wide

    condition:
        any of them
}
