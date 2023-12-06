rule DFSCoerce
{
    meta:
        description = "Detection patterns for the tool 'DFSCoerce' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DFSCoerce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot?
        // Reference: https://github.com/Wh04m1001/DFSCoerce
        $string1 = /\/DFSCoerce\.git/ nocase ascii wide
        // Description: PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot?
        // Reference: https://github.com/Wh04m1001/DFSCoerce
        $string2 = /dfscoerce\.py/ nocase ascii wide
        // Description: PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot?
        // Reference: https://github.com/Wh04m1001/DFSCoerce
        $string3 = /DFSCoerce\-main/ nocase ascii wide
        // Description: PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot?
        // Reference: https://github.com/Wh04m1001/DFSCoerce
        $string4 = /Wh04m1001\/DFSCoerce/ nocase ascii wide

    condition:
        any of them
}
