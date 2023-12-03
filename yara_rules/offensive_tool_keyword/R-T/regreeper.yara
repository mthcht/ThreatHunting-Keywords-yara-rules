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
        $string1 = /.{0,1000}\/regreeper\.jpg.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string2 = /.{0,1000}\/Reg\-Restore\-Persistence\-Mole.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string3 = /.{0,1000}\\save_reg\.hive.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string4 = /.{0,1000}A7AD39B5\-9BA1\-48A9\-B928\-CA25FDD8F31F.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string5 = /.{0,1000}RegReeper\.7z.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string6 = /.{0,1000}RegReeper\.cpp.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string7 = /.{0,1000}RegReeper\.exe.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string8 = /.{0,1000}RegReeper\.sln.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string9 = /.{0,1000}RegReeper\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: gain persistence and evade sysmon event code registry (creation update and deletion) REG_NOTIFY_CLASS Registry Callback of sysmon driver filter. RegSaveKeyExW() and RegRestoreKeyW() API which is not included in monitoring.
        // Reference: https://github.com/tccontre/Reg-Restore-Persistence-Mole
        $string10 = /.{0,1000}Reg\-Restore\-Persistence\-Mole\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
