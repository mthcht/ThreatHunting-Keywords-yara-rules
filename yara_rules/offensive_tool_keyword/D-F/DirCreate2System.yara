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
        $string1 = /\/DirCreate2System\.git/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string2 = /binderlabs\/DirCreate2System/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string3 = /dir_create2system\.txt/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string4 = /dircreate2system\.cpp/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string5 = /dircreate2system\.exe/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string6 = /dircreate2system\.sln/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string7 = /dircreate2system\.vcxproj/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string8 = /DirCreate2System\-main/ nocase ascii wide
        // Description: Weaponizing to get NT SYSTEM for Privileged Directory Creation Bugs with Windows Error Reporting
        // Reference: https://github.com/binderlabs/DirCreate2System
        $string9 = /dll_spawn_cmd\.cpp/ nocase ascii wide

    condition:
        any of them
}