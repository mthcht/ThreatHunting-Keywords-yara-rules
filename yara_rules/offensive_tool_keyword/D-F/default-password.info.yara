rule default_password_info
{
    meta:
        description = "Detection patterns for the tool 'default-password.info' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "default-password.info"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: default passwords database
        // Reference: https://default-password.info/
        $string1 = /https\:\/\/default\-password\.info\// nocase ascii wide

    condition:
        any of them
}
