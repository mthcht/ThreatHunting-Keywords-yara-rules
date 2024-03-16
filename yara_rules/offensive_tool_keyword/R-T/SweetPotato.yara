rule SweetPotato
{
    meta:
        description = "Detection patterns for the tool 'SweetPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SweetPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string1 = /\s\-\-exploit\=DCOM/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string2 = /\s\-\-exploit\=DCOM/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string3 = /\s\-\-exploit\=EfsRpc/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string4 = /\s\-\-exploit\=PrintSpoofer/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string5 = /\s\-\-exploit\=WinRM/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string6 = /\sSweetpotato\.exe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string7 = /\/Sweetpotato\.exe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string8 = /\/SweetPotato\.git/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string9 = /\/SweetPotato\-master\.zip/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string10 = /\[\+\]\sAttempting\sDCOM\sNTLM\srelaying\swith\sCLSID/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string11 = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sEfsRpc\sto\slaunch\s/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string12 = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sPrintSpoofer\sto\slaunch\s/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string13 = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string14 = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE\s/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string15 = /\\Sweetpotato\.exe/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string16 = /\\SweetPotato\\Program\.cs/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string17 = /\\SweetPotato\-master\.zip/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string18 = /1BF9C10F\-6F89\-4520\-9D2E\-AAF17D17BA5E/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string19 = /8f2a1d66e0a532a030da8e0e646f866ea91ee987ffb33b36d95f64a0538a3e20/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string20 = /CCob\/SweetPotato/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string21 = /PotatoAPI\.Mode\.DCOMRemote/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string22 = /Remote\sPotato\sby\s\@decoder_it\sand\s\@splinter_code/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string23 = /SweetPotato\sby\s\@_EthicalChaos_/ nocase ascii wide
        // Description: Local Service to SYSTEM privilege escalation from Windows 7 to Windows 10 / Server 2019
        // Reference: https://github.com/CCob/SweetPotato
        $string24 = /Weaponized\sJuciyPotato\sby\s\@decoder_it\sand\s\@Guitro\salong\swith\sBITS\sWinRM\sdiscovery/ nocase ascii wide

    condition:
        any of them
}
