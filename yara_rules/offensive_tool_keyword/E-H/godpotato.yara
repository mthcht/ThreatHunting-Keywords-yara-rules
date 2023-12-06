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
        $string1 = /\\Godpotato\\/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string2 = /BeichenDream\/GodPotato/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string3 = /GodPotato\s\-/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string4 = /GodPotato\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string5 = /godpotato\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string6 = /GodPotato\.git/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string7 = /GodPotatoContext\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string8 = /GodPotato\-master\.zip/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string9 = /GodPotato\-NET.{0,1000}\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string10 = /GodPotatoUnmarshalTrigger\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string11 = /SharpToken\.exe/ nocase ascii wide

    condition:
        any of them
}
