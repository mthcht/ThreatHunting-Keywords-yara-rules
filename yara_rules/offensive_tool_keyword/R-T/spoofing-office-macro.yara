rule spoofing_office_macro
{
    meta:
        description = "Detection patterns for the tool 'spoofing-office-macro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spoofing-office-macro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string1 = /\/spoofing\-office\-macro\.git/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string2 = /\\macro64\.vba/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string3 = /\\spoofing\-office\-macro\-master/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string4 = /8b4cb728e2db083daf0b42a3d3e6982e161ba42f90264e6da1508800e4b4d394/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string5 = /christophetd\/spoofing\-office\-macro/ nocase ascii wide
        // Description: PoC of a VBA macro spawning a process with a spoofed parent and command line
        // Reference: https://github.com/christophetd/spoofing-office-macro
        $string6 = /http\:\/\/bit\.ly\/2TxpA4h/ nocase ascii wide

    condition:
        any of them
}
