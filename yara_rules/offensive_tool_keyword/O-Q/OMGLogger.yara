rule OMGLogger
{
    meta:
        description = "Detection patterns for the tool 'OMGLogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OMGLogger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Key logger which sends each and every key stroke of target remotely/locally.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/OMGLogger
        $string1 = /.{0,1000}\/tmmmp\s.{0,1000}/ nocase ascii wide
        // Description: Key logger which sends each and every key stroke of target remotely/locally.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/OMGLogger
        $string2 = /.{0,1000}fsockopen\(.{0,1000}0\.0\.0\.0.{0,1000}4444.{0,1000}exec\(.{0,1000}/ nocase ascii wide
        // Description: Key logger which sends each and every key stroke of target remotely/locally.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/OMGLogger
        $string3 = /.{0,1000}OMGLoggerDecoder.{0,1000}/ nocase ascii wide
        // Description: Key logger which sends each and every key stroke of target remotely/locally.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/OMGLogger
        $string4 = /.{0,1000}wget.{0,1000}\/drapl0n\/DuckyLogger\/blob\/main\/xinput\\\?raw\=true.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
