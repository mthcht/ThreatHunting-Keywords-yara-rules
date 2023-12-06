rule regreeper
{
    meta:
        description = "Detection patterns for the tool 'regreeper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "regreeper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string1 = /\/regreeper\.jpg/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string2 = /\/Reg\-Restore\-Persistence\-Mole/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string3 = /\\save_reg\.hive/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string4 = /A7AD39B5\-9BA1\-48A9\-B928\-CA25FDD8F31F/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string5 = /RegReeper\.7z/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string6 = /RegReeper\.cpp/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string7 = /RegReeper\.exe/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string8 = /RegReeper\.sln/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string9 = /RegReeper\.vcxproj/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string10 = /Reg\-Restore\-Persistence\-Mole\-main/ nocase ascii wide

    condition:
        any of them
}
