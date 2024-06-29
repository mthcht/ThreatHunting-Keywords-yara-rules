rule godpotato
{
    meta:
        description = "Detection patterns for the tool 'godpotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "godpotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string1 = /\.exe\s\-cmd\s\"cmd\s\/c\swhoami\"/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string2 = /\/GodPotato\.git/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string3 = /\\Godpotato\\/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string4 = /2AE886C3\-3272\-40BE\-8D3C\-EBAEDE9E61E1/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string5 = /BeichenDream\/GodPotato/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string6 = /GodPotato\s\-/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string7 = /godpotato\.cna/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string8 = /GodPotato\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string9 = /godpotato\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string10 = /GodPotato\.git/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string11 = /GodPotato\-Aggressor\-Script/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string12 = /GodPotatoContext\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string13 = /GodPotato\-master\.zip/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string14 = /GodPotato\-NET.{0,1000}\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string15 = /GodPotato\-NET2\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string16 = /GodPotato\-NET35\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string17 = /GodPotato\-NET4\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string18 = /GodPotato\-NET4\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string19 = /GodPotatoUnmarshalTrigger\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string20 = /SharpToken\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string21 = /Tasked\sBeacon\sto\sescalate\sto\sSYSTEM/ nocase ascii wide

    condition:
        any of them
}
