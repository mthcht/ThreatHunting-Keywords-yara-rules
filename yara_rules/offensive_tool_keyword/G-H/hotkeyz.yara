rule hotkeyz
{
    meta:
        description = "Detection patterns for the tool 'hotkeyz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hotkeyz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string1 = /\/Hotkeyz\.exe/ nocase ascii wide
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string2 = /\/hotkeyz\.git/ nocase ascii wide
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string3 = /\\Hotkeyz\.exe/ nocase ascii wide
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string4 = "2deff2ca-c313-4d85-aeee-414bac32e7ae" nocase ascii wide
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string5 = "59fb3de646d1f2643ed4d11d87e98fa71452f8f4fd623c177f5b626f5b507c27" nocase ascii wide
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string6 = "efb9e62e4e669c34fb75f1b1c7ae27911bf6ea022f0094d4c7c33ee8c38897e6" nocase ascii wide
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string7 = "f05e2bbc6da71e91b59512e9f50219dd6852481d52cca02a0b780dd29ce52fb7" nocase ascii wide
        // Description: Hotkey-based keylogger for Windows
        // Reference: https://github.com/yo-yo-yo-jbo/hotkeyz
        $string8 = "yo-yo-yo-jbo/hotkeyz" nocase ascii wide

    condition:
        any of them
}
