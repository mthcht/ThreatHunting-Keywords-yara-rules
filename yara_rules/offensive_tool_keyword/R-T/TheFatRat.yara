rule TheFatRat
{
    meta:
        description = "Detection patterns for the tool 'TheFatRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TheFatRat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and dll.
        // Reference: https://github.com/Screetsec/TheFatRat
        $string1 = "/backdoor_apk"
        // Description: Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and dll.
        // Reference: https://github.com/Screetsec/TheFatRat
        $string2 = /\/cred_dump\.rc/
        // Description: Easy tool to generate backdoor and easy tool to post exploitation attack like browser attack and dll.
        // Reference: https://github.com/Screetsec/TheFatRat
        $string3 = "/TheFatRat"

    condition:
        any of them
}
