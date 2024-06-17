rule SharpSCCM
{
    meta:
        description = "Detection patterns for the tool 'SharpSCCM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string1 = /\sget\sclass\-instances\sSMS_R_System\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string2 = /\sget\sclass\-properties\sSMS_Admin/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string3 = /\sget\scollection\-members\s\-n\sUSERS/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string4 = /\sget\sprimary\-users\s\-u\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string5 = /\sget\ssite\-push\-settings/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string6 = /\sinvoke\sadmin\-service\s\-q\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string7 = /\sinvoke\sadmin\-service\s\-q\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string8 = /\sinvoke\squery\s.{0,1000}FROM\sSMS_Admin/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string9 = /\slocal\sclass\-instances\sSMS_Authority/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string10 = /\slocal\sclass\-properties\sSMS_Authority/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string11 = /\slocal\sgrep\s.{0,1000}ccmsetup\sstarted\s.{0,1000}ccmsetup\.log/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string12 = /\slocal\squery\s.{0,1000}\sFROM\sSMS_Authority/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string13 = /\slocal\ssecrets\s\-m\sdisk/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string14 = /\slocal\ssecrets\s\-m\swmi/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string15 = /\s\-p\sLastLogonTimestamp\s\-p\sLastLogonUserName\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string16 = /\sremove\sdevice\sGUID\:001B2EE1\-AE95\-4146\-AE7B\-5928F1E4F396/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string17 = /\/SharpSCCM\.git/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string18 = /\/SharpSCCM\/releases\/download\// nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string19 = /\\SharpSCCM\-main/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string20 = /03652836\-898E\-4A9F\-B781\-B7D86E750F60/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string21 = /2170a03a337a89bb3b6a02035ae85946815f8643897ded40fc0a2c29e2e5a960/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string22 = /3b765fc9d51180b7ff8c93aa1ab9369fdff33f5ec4ebc4c2e913f8355ca12903/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string23 = /54fe99f13b593d3acfc583e17d0bfd2e315d0ee20e737610bede18eb173ae864/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string24 = /E4D9EF39\-0FCE\-4573\-978B\-ABF8DF6AEC23/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string25 = /f945696926267701f5b3327ecb4af54169fd24f780db0f4caecf1fe447848007/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string26 = /Mayyhem\/SharpSCCM/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string27 = /SharpSCCM/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string28 = /SharpSCCM\.csproj/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string29 = /SharpSCCM\.exe/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for Lateral Movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string30 = /SharpSCCM_merged\.exe/ nocase ascii wide

    condition:
        any of them
}
