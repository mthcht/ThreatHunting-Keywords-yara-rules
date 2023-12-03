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
        $string1 = /.{0,1000}\/DFSCoerce\.git.{0,1000}/ nocase ascii wide
        // Description: PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot?
        // Reference: https://github.com/Wh04m1001/DFSCoerce
        $string2 = /.{0,1000}dfscoerce\.py.{0,1000}/ nocase ascii wide
        // Description: PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot?
        // Reference: https://github.com/Wh04m1001/DFSCoerce
        $string3 = /.{0,1000}DFSCoerce\-main.{0,1000}/ nocase ascii wide
        // Description: PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot?
        // Reference: https://github.com/Wh04m1001/DFSCoerce
        $string4 = /.{0,1000}Wh04m1001\/DFSCoerce.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
