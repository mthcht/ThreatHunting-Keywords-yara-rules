rule OffensiveNotion
{
    meta:
        description = "Detection patterns for the tool 'OffensiveNotion' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveNotion"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string1 = /\s\/create\s\/tn\sNotion\s\/tr\s\\.{0,1000}cmd\.exe.{0,1000}\s\-c\s.{0,1000}\\.{0,1000}\s\/sc\sonlogon\s\/ru\sSystem\\/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string2 = /\$FilterArgs\s\=\s\@\{\sname\=\'Notion\'.{0,1000}EventNameSpace\=\'root\\\\CimV2\'.{0,1000}QueryLanguage\=.{0,1000}WQL.{0,1000}\sQuery\=.{0,1000}SELECT\s.{0,1000}\sFROM\s__InstanceModificationE/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string3 = /\/OffensiveNotion\.git/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string4 = /\/OffensiveNotion\/agent/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string5 = /\/OffensiveNotion\/osxcross\/target\/bin/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string6 = /\/OffensiveNotion\/utils/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string7 = /cddownloadelevategetprivsinjectpersistportscanpspwdrunassaveshellshutdownsleep/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string8 = /mttaggart\/OffensiveNotion/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string9 = /offensive_notion\.exe/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string10 = /offensive_notion_darwin_/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string11 = /offensive_notion_linux_/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string12 = /offensive_notion_win_.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
