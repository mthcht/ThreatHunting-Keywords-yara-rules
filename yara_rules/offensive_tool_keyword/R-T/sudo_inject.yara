rule sudo_inject
{
    meta:
        description = "Detection patterns for the tool 'sudo_inject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo_inject"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Privilege Escalation by injecting process possessing sudo tokens Inject process that have valid sudo token and activate our own sudo token
        // Reference: https://github.com/nongiach/sudo_inject
        $string1 = /.{0,1000}sudo_inject.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
