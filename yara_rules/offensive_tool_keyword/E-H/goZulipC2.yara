rule goZulipC2
{
    meta:
        description = "Detection patterns for the tool 'goZulipC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goZulipC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2 leveraging Zulip Messaging Platform as Backend.
        // Reference: https://github.com/n1k7l4i/goZulipC2
        $string1 = /.{0,1000}\/AntiSandbox\.go.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Zulip Messaging Platform as Backend.
        // Reference: https://github.com/n1k7l4i/goZulipC2
        $string2 = /.{0,1000}\/goZulipC2\.git.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Zulip Messaging Platform as Backend.
        // Reference: https://github.com/n1k7l4i/goZulipC2
        $string3 = /.{0,1000}\\AntiSandbox\.go.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Zulip Messaging Platform as Backend.
        // Reference: https://github.com/n1k7l4i/goZulipC2
        $string4 = /.{0,1000}\\goZulipC2.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Zulip Messaging Platform as Backend.
        // Reference: https://github.com/n1k7l4i/goZulipC2
        $string5 = /.{0,1000}goZulipC2\.go.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Zulip Messaging Platform as Backend.
        // Reference: https://github.com/n1k7l4i/goZulipC2
        $string6 = /.{0,1000}goZulipC2\-main.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Zulip Messaging Platform as Backend.
        // Reference: https://github.com/n1k7l4i/goZulipC2
        $string7 = /.{0,1000}n1k7l4i\/goZulipC2.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
