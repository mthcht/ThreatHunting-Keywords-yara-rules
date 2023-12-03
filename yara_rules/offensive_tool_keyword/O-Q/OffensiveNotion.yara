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
        $string1 = /.{0,1000}\s\/create\s\/tn\sNotion\s\/tr\s\\.{0,1000}cmd\.exe.{0,1000}\s\-c\s.{0,1000}\\.{0,1000}\s\/sc\sonlogon\s\/ru\sSystem\\.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string2 = /.{0,1000}\$FilterArgs\s\=\s\@{\sname\=\'Notion\'.{0,1000}EventNameSpace\=\'root\\\\CimV2\'.{0,1000}QueryLanguage\=.{0,1000}WQL.{0,1000}\sQuery\=.{0,1000}SELECT\s.{0,1000}\sFROM\s__InstanceModificationE.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string3 = /.{0,1000}\/OffensiveNotion\.git/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string4 = /.{0,1000}\/OffensiveNotion\/agent.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string5 = /.{0,1000}\/OffensiveNotion\/osxcross\/target\/bin.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string6 = /.{0,1000}\/OffensiveNotion\/utils.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string7 = /.{0,1000}cddownloadelevategetprivsinjectpersistportscanpspwdrunassaveshellshutdownsleep.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string8 = /.{0,1000}mttaggart\/OffensiveNotion.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string9 = /.{0,1000}offensive_notion\.exe.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string10 = /.{0,1000}offensive_notion_darwin_.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string11 = /.{0,1000}offensive_notion_linux_.{0,1000}/ nocase ascii wide
        // Description: Notion (yes the notetaking app) as a C2.
        // Reference: https://github.com/mttaggart/OffensiveNotion
        $string12 = /.{0,1000}offensive_notion_win_.{0,1000}\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
