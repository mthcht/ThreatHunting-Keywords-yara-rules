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
        $string1 = /.{0,1000}chromiumkeydump\s.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string2 = /.{0,1000}ChromiumKeyDump\.cna.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string3 = /.{0,1000}ChromiumKeyDump\.cpp.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string4 = /.{0,1000}ChromiumKeyDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Collection of Beacon Object Files (BOF) for Cobalt Strike
        // Reference: https://github.com/crypt0p3g/bof-collection
        $string5 = /.{0,1000}crypt0p3g\/bof\-collection.{0,1000}/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string6 = /.{0,1000}Minidump\.exe.{0,1000}/ nocase ascii wide
        // Description: C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS dumps
        // Reference: https://github.com/cube0x0/MiniDump
        $string7 = /.{0,1000}Minidump\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
