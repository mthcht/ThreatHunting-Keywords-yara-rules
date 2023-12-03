rule adeleg
{
    meta:
        description = "Detection patterns for the tool 'adeleg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adeleg"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string1 = /.{0,1000}\/ADeleg\.exe.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string2 = /.{0,1000}\/adeleg\.git.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string3 = /.{0,1000}\/adeleg\.pdb.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string4 = /.{0,1000}\\ADeleg\.exe.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string5 = /.{0,1000}\\adeleg\.pdb.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string6 = /.{0,1000}\\adeleg\\adeleg\\.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string7 = /.{0,1000}\\adeleg\\winldap\\.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string8 = /.{0,1000}\\adeleg\-main.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string9 = /.{0,1000}ADeleg\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string10 = /.{0,1000}mtth\-bfft\/adeleg.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
