rule pth_toolkit
{
    meta:
        description = "Detection patterns for the tool 'pth-toolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pth-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string1 = /pth\-rpcclient/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string2 = /pth\-smbclient/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string3 = /pth\-smbget/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string4 = /pth\-toolkit/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string5 = /pth\-winexe/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string6 = /pth\-wmic/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string7 = /pth\-wmis/ nocase ascii wide

    condition:
        any of them
}
