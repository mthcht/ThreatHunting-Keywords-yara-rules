rule wifite2
{
    meta:
        description = "Detection patterns for the tool 'wifite2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifite2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This repo is a complete re-write of wifite. a Python script for auditing wireless networks.Run wifite. select your targets. and Wifite will automatically start trying to capture or crack the password.
        // Reference: https://github.com/derv82/wifite2
        $string1 = /.{0,1000}\/wifite\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: This repo is a complete re-write of wifite. a Python script for auditing wireless networks.Run wifite. select your targets. and Wifite will automatically start trying to capture or crack the password.
        // Reference: https://github.com/derv82/wifite2
        $string2 = /.{0,1000}\/wifite2.{0,1000}/ nocase ascii wide
        // Description: This repo is a complete re-write of wifite. a Python script for auditing wireless networks.Run wifite. select your targets. and Wifite will automatically start trying to capture or crack the password.
        // Reference: https://github.com/derv82/wifite2
        $string3 = /.{0,1000}wifite\s\-\-crack.{0,1000}/ nocase ascii wide
        // Description: This repo is a complete re-write of wifite. a Python script for auditing wireless networks.Run wifite. select your targets. and Wifite will automatically start trying to capture or crack the password.
        // Reference: https://github.com/derv82/wifite2
        $string4 = /.{0,1000}wifite\s\-e\s.{0,1000}/ nocase ascii wide
        // Description: This repo is a complete re-write of wifite. a Python script for auditing wireless networks.Run wifite. select your targets. and Wifite will automatically start trying to capture or crack the password.
        // Reference: https://github.com/derv82/wifite2
        $string5 = /.{0,1000}wifite\s\-\-wep\s.{0,1000}/ nocase ascii wide
        // Description: This repo is a complete re-write of wifite. a Python script for auditing wireless networks.Run wifite. select your targets. and Wifite will automatically start trying to capture or crack the password.
        // Reference: https://github.com/derv82/wifite2
        $string6 = /.{0,1000}Wifite\.py.{0,1000}/ nocase ascii wide
        // Description: This repo is a complete re-write of wifite. a Python script for auditing wireless networks.Run wifite. select your targets. and Wifite will automatically start trying to capture or crack the password.
        // Reference: https://github.com/derv82/wifite2
        $string7 = /.{0,1000}wifite2\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
