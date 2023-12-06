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
        $string1 = /\s\-\-access\-token/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string2 = /\s\-\-drag\-and\-drop/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string3 = /\s\-\-drop\-drag\-and\-drop\-target/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string4 = /\s\-\-extra\-verbose/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string5 = /\s\-\-no\-net/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string6 = /\s\-\-no\-prop/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string7 = /\s\-\-no\-prop\-servers/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string8 = /\s\-\-no\-vm\-kill/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string9 = /\s\-\-no\-vm\-snapshot\-kill/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string10 = /\s\-\-no\-wall/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string11 = /\s\-\-propagated/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string12 = /\.exe\s\-\-ui\s/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string13 = /bcdedit\.exe\s\/set\s{default}\srecoveryenabled\sNo/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string14 = /iisreset\.exe\s\/stop/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string15 = /wmic\.exe.{0,1000}\sShadowcopy\sDelete/ nocase ascii wide

    condition:
        any of them
}
