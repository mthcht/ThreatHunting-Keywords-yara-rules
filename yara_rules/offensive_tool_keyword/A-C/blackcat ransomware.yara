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
        $string1 = /.{0,1000}\s\-\-access\-token.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string2 = /.{0,1000}\s\-\-drag\-and\-drop.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string3 = /.{0,1000}\s\-\-drop\-drag\-and\-drop\-target.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string4 = /.{0,1000}\s\-\-extra\-verbose.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string5 = /.{0,1000}\s\-\-no\-net.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string6 = /.{0,1000}\s\-\-no\-prop.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string7 = /.{0,1000}\s\-\-no\-prop\-servers.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string8 = /.{0,1000}\s\-\-no\-vm\-kill.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string9 = /.{0,1000}\s\-\-no\-vm\-snapshot\-kill.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string10 = /.{0,1000}\s\-\-no\-wall.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string11 = /.{0,1000}\s\-\-propagated.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string12 = /.{0,1000}\.exe\s\-\-ui\s.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string13 = /.{0,1000}bcdedit\.exe\s\/set\s{default}\srecoveryenabled\sNo.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string14 = /.{0,1000}iisreset\.exe\s\/stop.{0,1000}/ nocase ascii wide
        // Description: BlackCat Ransomware behavior
        // Reference: https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/
        $string15 = /.{0,1000}wmic\.exe.{0,1000}\sShadowcopy\sDelete.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
