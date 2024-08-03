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
        $string3 = /\\\\pipe\\\\GodPotato/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string4 = /\\Godpotato\\/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string5 = /\\pipe\\GodPotato/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string6 = /130af28d5a846c7f961a6a0a1188e1688501d8c0c4a3df4c1451005f1fc162fa/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string7 = /24fe09ac811357d1a5ddd63652604def847cb2d4f81c01ecfe563ead611783e3/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string8 = /24fe09ac811357d1a5ddd63652604def847cb2d4f81c01ecfe563ead611783e3/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string9 = /2AE886C3\-3272\-40BE\-8D3C\-EBAEDE9E61E1/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string10 = /3027a212272957298bf4d32505370fa63fb162d6a6a6ec091af9d7626317a858/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string11 = /3027a212272957298bf4d32505370fa63fb162d6a6a6ec091af9d7626317a858/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string12 = /4830297df839add17bdea8daa07deea8a8b1ff156a68dfeae1e7ae420270191f/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string13 = /56acdd67faeb3b1dd15632102f4cb068acdbdc24e0f78f856824610a8be9ab91/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string14 = /6b816c41bab51043022a96f74980439be30aa8af02a1aac0ee56912a710115af/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string15 = /828c2d6318c0f827de40468b1bccf68a33851bd78d2dd218fb008f3928250d42/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string16 = /9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string17 = /BeichenDream\/GodPotato/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string18 = /ef3b03b91b7779e6ff07bacd3921a4851458c58281ac77195d3c20da19261b22/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string19 = /GodPotato\s\-/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string20 = /godpotato\.cna/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string21 = /GodPotato\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string22 = /godpotato\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string23 = /GodPotato\.git/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string24 = /GodPotato\-Aggressor\-Script/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string25 = /GodPotatoContext\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string26 = /GodPotato\-master\.zip/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string27 = /GodPotato\-NET.{0,1000}\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string28 = /GodPotato\-NET2\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string29 = /GodPotato\-NET35\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string30 = /GodPotato\-NET4\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string31 = /GodPotato\-NET4\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string32 = /GodPotatoUnmarshalTrigger\.cs/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/BeichenDream/GodPotato
        $string33 = /SharpToken\.exe/ nocase ascii wide
        // Description: GodPotato is an advanced privilege escalation tool that utilizes research on DCOM and builds upon years of Potato techniques. It enables privilege escalation to NT AUTHORITY\SYSTEM on Windows systems from 2012 to 2022 by leveraging the ImpersonatePrivilege permission. It addresses limitations of previous Potato versions and can run on almost any Windows OS by exploiting rpcss vulnerabilities.
        // Reference: https://github.com/weaselsec/GodPotato-Aggressor-Script
        $string34 = /Tasked\sBeacon\sto\sescalate\sto\sSYSTEM/ nocase ascii wide

    condition:
        any of them
}
