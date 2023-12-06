rule PRT
{
    meta:
        description = "Detection patterns for the tool 'PRT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PRT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PRET is a new tool for printer security testing developed in the scope of a Masters Thesis at Ruhr University Bochum. It connects to a device via network or USB and exploits the features of a given printer language. Currently PostScript. PJL and PCL are supported which are spoken by most laser printers. This allows cool stuff like capturing or manipulating print jobs. accessing the printers file system and memory or even causing physical damage to the device. All attacks are documented in detail in the Hacking Printers Wiki. The main idea of PRET is to facilitate the communication between the end-user and the printer. Thus. after entering a UNIX-like command. PRET translates it to PostScript. PJL or PCL. sends it to the printer. evaluates the result and translates it back to a user-friendly format. PRET offers a whole bunch of commands useful for printer attacks and fuzzing
        // Reference: https://github.com/RUB-NDS/PRT
        $string1 = /Exploitation\sToolkit/ nocase ascii wide

    condition:
        any of them
}
