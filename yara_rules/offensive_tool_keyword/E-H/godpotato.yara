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
        $string1 = /.{0,1000}\\Godpotato\\.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string2 = /.{0,1000}BeichenDream\/GodPotato.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string3 = /.{0,1000}GodPotato\s\-.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string4 = /.{0,1000}GodPotato\.cs.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string5 = /.{0,1000}godpotato\.exe.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string6 = /.{0,1000}GodPotato\.git.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string7 = /.{0,1000}GodPotatoContext\.cs.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string8 = /.{0,1000}GodPotato\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string9 = /.{0,1000}GodPotato\-NET.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string10 = /.{0,1000}GodPotatoUnmarshalTrigger\.cs.{0,1000}/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string11 = /.{0,1000}SharpToken\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
