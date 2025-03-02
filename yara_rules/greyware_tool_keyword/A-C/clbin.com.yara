rule clbin_com
{
    meta:
        description = "Detection patterns for the tool 'clbin.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "clbin.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: clbin.com be used for C&C purposes. The attacker will place commands on a textbin paste and have the malware fetch the commands.
        // Reference: https://clbin.com/
        $string1 = /\s\|\sclbin/ nocase ascii wide
        // Description: clbin.com be used for C&C purposes. The attacker will place commands on a textbin paste and have the malware fetch the commands.
        // Reference: https://clbin.com/
        $string2 = /https\:\/\/clbin\.com\// nocase ascii wide

    condition:
        any of them
}
