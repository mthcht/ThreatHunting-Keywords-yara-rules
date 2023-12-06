rule ghidra
{
    meta:
        description = "Detection patterns for the tool 'ghidra' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghidra"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. This framework includes a suite of full-featured. high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows. macOS. and Linux. Capabilities include disassembly. assembly. decompilation. graphing. and scripting. along with hundreds of other features. Ghidra supports a wide variety of processor instruction sets and executable formats and can be run in both user-interactive and automated modes. Users may also develop their own Ghidra plug-in components and/or scripts using Java or Python.
        // Reference: https://github.com/NationalSecurityAgency/ghidra
        $string1 = /\/ghidra/ nocase ascii wide

    condition:
        any of them
}
