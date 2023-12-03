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
        $string1 = /.{0,1000}pth\-rpcclient.{0,1000}/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string2 = /.{0,1000}pth\-smbclient.{0,1000}/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string3 = /.{0,1000}pth\-smbget.{0,1000}/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string4 = /.{0,1000}pth\-toolkit.{0,1000}/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string5 = /.{0,1000}pth\-winexe.{0,1000}/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string6 = /.{0,1000}pth\-wmic.{0,1000}/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string7 = /.{0,1000}pth\-wmis.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
