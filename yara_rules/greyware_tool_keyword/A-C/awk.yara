rule awk
{
    meta:
        description = "Detection patterns for the tool 'awk' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commonly used to upgrade a restricted shell
        // Reference: N/A
        $string1 = /sudo\sawk\s\'BEGIN\s\{system\(\\"\/bin\/bash\\"\)\}\'/

    condition:
        any of them
}
