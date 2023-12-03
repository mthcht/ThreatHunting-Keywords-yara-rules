rule DirCreate2System
{
    meta:
        description = "Detection patterns for the tool 'DirCreate2System' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DirCreate2System"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string1 = /.{0,1000}\/DirCreate2System\.git.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string2 = /.{0,1000}binderlabs\/DirCreate2System.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string3 = /.{0,1000}dir_create2system\.txt.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string4 = /.{0,1000}dircreate2system\.cpp.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string5 = /.{0,1000}dircreate2system\.exe.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string6 = /.{0,1000}dircreate2system\.sln.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string7 = /.{0,1000}dircreate2system\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string8 = /.{0,1000}DirCreate2System\-main.{0,1000}/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string9 = /.{0,1000}dll_spawn_cmd\.cpp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
