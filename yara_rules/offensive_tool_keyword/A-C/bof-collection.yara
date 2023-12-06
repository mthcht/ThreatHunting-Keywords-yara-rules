rule bof_collection
{
    meta:
        description = "Detection patterns for the tool 'bof-collection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bof-collection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string1 = /chromiumkeydump\s/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2 = /ChromiumKeyDump\.cna/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string3 = /ChromiumKeyDump\.cpp/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string4 = /ChromiumKeyDump\.exe/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string5 = /crypt0p3g\/bof\-collection/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string6 = /Minidump\.exe/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string7 = /Minidump\.sln/ nocase ascii wide

    condition:
        any of them
}
