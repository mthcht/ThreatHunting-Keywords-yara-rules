rule blackcat_ransomware
{
    meta:
        description = "Detection patterns for the tool 'blackcat ransomware' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blackcat ransomware"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string1 = /\s\-\-drop\-drag\-and\-drop\-target/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string2 = /\s\-\-no\-vm\-kill/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string3 = /\s\-\-no\-vm\-snapshot\-kill/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string4 = /bcdedit\.exe\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string5 = /iisreset\.exe\s\/stop/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string6 = /wmic\.exe.{0,1000}\sShadowcopy\sDelete/ nocase ascii wide

    condition:
        any of them
}
