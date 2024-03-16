rule Adeleginator
{
    meta:
        description = "Detection patterns for the tool 'Adeleginator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adeleginator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string1 = /\sADeleg\.exe/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string2 = /\$ADelegReport/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string3 = /\$InsecureResourceDelegations/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string4 = /\$InsecureTrusteeDelegations/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string5 = /\/ADeleg\.exe/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string6 = /\/ADeleginator\.git/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string7 = /\/Invoke\-Adeleginator/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string8 = /\/mtth\-bfft\/adeleg\/releases/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string9 = /\[\!\]\sInsecure\sresource\sdelegations\sfound\.\sExporting\sreport\:/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string10 = /\[\!\]\sInsecure\strustee\sdelegations\sfound\.\sExporting\sreport\:\s/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string11 = /\[\+\]\sNo\sinsecure\sresource\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string12 = /\[\+\]\sNo\sinsecure\strustee\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string13 = /\[i\]\sChecking\sfor\sinsecure\strustee\/resource\sdelegations/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string14 = /\[i\]\sRunning\sADeleg\sand\screating\s/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string15 = /\\ADeleg\.exe/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string16 = /\\Adeleginator\-main/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string17 = /ADeleg_InsecureResourceDelegationReport_/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string18 = /ADeleg_InsecureTrusteeDelegationReport_/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string19 = /Create\-ADelegReport/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string20 = /Find\-InsecureResourceDelegations/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string21 = /Go\,\sgo\sADeleginator\!/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string22 = /Invoke\-Adeleginator/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string23 = /techspence\/Adeleginator/ nocase ascii wide
        // Description: tool that uses ADeleg to find insecure trustee and resource delegations in Active Directory
        // Reference: https://github.com/techspence/Adeleginator
        $string24 = /Thank\syou\sfor\susing\sADeleginator\.\sGodspeed\!\s\:O/ nocase ascii wide

    condition:
        any of them
}
