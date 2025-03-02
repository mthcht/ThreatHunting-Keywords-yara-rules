rule zerobin_net
{
    meta:
        description = "Detection patterns for the tool 'zerobin.net' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zerobin.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: accessing paste raw content
        // Reference: https://zerobin.net/
        $string1 = /http\:\/\/zerobinftagjpeeebbvyzjcqyjpmjvynj5qlexwyxe7l3vqejxnqv5qd\.onion/ nocase ascii wide
        // Description: accessing paste raw content
        // Reference: https://zerobin.net/
        $string2 = /https\:\/\/zerobin\.net\/\?/ nocase ascii wide
        // Description: sending data to a pastebin
        // Reference: https://zerobin.net/
        $string3 = /https\:\/\/zerobin\.net\/js\/privatebin\.js/ nocase ascii wide

    condition:
        any of them
}
