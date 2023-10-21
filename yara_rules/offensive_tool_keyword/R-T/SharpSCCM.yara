rule SharpSCCM
{
    meta:
        description = "Detection patterns for the tool 'SharpSCCM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSCCM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string1 = /\sget\sclass\-instances\sSMS_R_System\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string2 = /\sget\sclass\-properties\sSMS_Admin/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string3 = /\sget\scollection\-members\s\-n\sUSERS/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string4 = /\sget\sprimary\-users\s\-u\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string5 = /\sget\ssite\-push\-settings/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string6 = /\sinvoke\sadmin\-service\s\-q\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string7 = /\sinvoke\sadmin\-service\s\-q\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string8 = /\sinvoke\squery\s.*FROM\sSMS_Admin/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string9 = /\slocal\sclass\-instances\sSMS_Authority/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string10 = /\slocal\sclass\-properties\sSMS_Authority/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string11 = /\slocal\sgrep\s.*ccmsetup\sstarted\s.*ccmsetup\.log/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string12 = /\slocal\squery\s.*\sFROM\sSMS_Authority/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string13 = /\slocal\ssecrets\s\-m\sdisk/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string14 = /\slocal\ssecrets\s\-m\swmi/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string15 = /\s\-p\sLastLogonTimestamp\s\-p\sLastLogonUserName\s/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string16 = /\sremove\sdevice\sGUID:001B2EE1\-AE95\-4146\-AE7B\-5928F1E4F396/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string17 = /SharpSCCM/ nocase ascii wide

    condition:
        any of them
}