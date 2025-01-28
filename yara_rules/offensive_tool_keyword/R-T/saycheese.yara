rule saycheese
{
    meta:
        description = "Detection patterns for the tool 'saycheese' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "saycheese"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string1 = /\ssaycheese\.sh/ nocase ascii wide
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string2 = "/ngrok http 3333 > /dev/null 2>&1"
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string3 = /\/saycheese\.html/ nocase ascii wide
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string4 = /\/saycheese\.sh/ nocase ascii wide
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string5 = "d10833b7d54745c35eec76ce48c1d8a4d90a9455bcd8b81cacdc95b9304b3be3" nocase ascii wide
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string6 = /https\:\/\/saycheese.{0,1000}\.serveo\.net/ nocase ascii wide
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string7 = /saycheese\-master\.zip/ nocase ascii wide
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string8 = /ssh\s\-o\sStrictHostKeyChecking\=no\s\-o\sServerAliveInterval\=60\s\-R\s.{0,1000}serveo\.net/ nocase ascii wide
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string9 = "thelinuxchoice/saycheese"
        // Description: Grab target's webcam shots by link
        // Reference: https://github.com/hangetzzu/saycheese
        $string10 = /url\:\s\'forwarding_link\/post\.php\'\,/ nocase ascii wide

    condition:
        any of them
}
