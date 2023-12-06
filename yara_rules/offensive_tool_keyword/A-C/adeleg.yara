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
        $string1 = /\/ADeleg\.exe/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string2 = /\/adeleg\.git/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string3 = /\/adeleg\.pdb/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string4 = /\\ADeleg\.exe/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string5 = /\\adeleg\.pdb/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string6 = /\\adeleg\\adeleg\\/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string7 = /\\adeleg\\winldap\\/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string8 = /\\adeleg\-main/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string9 = /ADeleg\.exe\s\-/ nocase ascii wide
        // Description: an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest
        // Reference: https://github.com/mtth-bfft/adeleg
        $string10 = /mtth\-bfft\/adeleg/ nocase ascii wide

    condition:
        any of them
}
