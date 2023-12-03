rule Ghostpack_CompiledBinaries
{
    meta:
        description = "Detection patterns for the tool 'Ghostpack-CompiledBinaries' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ghostpack-CompiledBinaries"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Compiled Binaries for Ghostpack
        // Reference: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
        $string1 = /.{0,1000}Ghostpack\-CompiledBinaries.{0,1000}/ nocase ascii wide
        // Description: Compiled Binaries for Ghostpack
        // Reference: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
        $string2 = /.{0,1000}RestrictedAdmin\.exe.{0,1000}/ nocase ascii wide
        // Description: Compiled Binaries for Ghostpack
        // Reference: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
        $string3 = /.{0,1000}SharpRoast\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
