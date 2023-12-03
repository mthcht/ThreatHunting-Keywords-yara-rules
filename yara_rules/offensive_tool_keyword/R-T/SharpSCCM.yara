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
        $string1 = /.{0,1000}\sget\sclass\-instances\sSMS_R_System\s.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string2 = /.{0,1000}\sget\sclass\-properties\sSMS_Admin.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string3 = /.{0,1000}\sget\scollection\-members\s\-n\sUSERS.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string4 = /.{0,1000}\sget\sprimary\-users\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string5 = /.{0,1000}\sget\ssite\-push\-settings.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string6 = /.{0,1000}\sinvoke\sadmin\-service\s\-q\s.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string7 = /.{0,1000}\sinvoke\sadmin\-service\s\-q\s.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string8 = /.{0,1000}\sinvoke\squery\s.{0,1000}FROM\sSMS_Admin.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string9 = /.{0,1000}\slocal\sclass\-instances\sSMS_Authority.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string10 = /.{0,1000}\slocal\sclass\-properties\sSMS_Authority.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string11 = /.{0,1000}\slocal\sgrep\s.{0,1000}ccmsetup\sstarted\s.{0,1000}ccmsetup\.log.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string12 = /.{0,1000}\slocal\squery\s.{0,1000}\sFROM\sSMS_Authority.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string13 = /.{0,1000}\slocal\ssecrets\s\-m\sdisk.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string14 = /.{0,1000}\slocal\ssecrets\s\-m\swmi.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string15 = /.{0,1000}\s\-p\sLastLogonTimestamp\s\-p\sLastLogonUserName\s.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string16 = /.{0,1000}\sremove\sdevice\sGUID:001B2EE1\-AE95\-4146\-AE7B\-5928F1E4F396.{0,1000}/ nocase ascii wide
        // Description: SharpSCCM is a post-exploitation tool designed to leverage Microsoft Endpoint Configuration Manager (a.k.a. ConfigMgr. formerly SCCM) for lateral movement and credential gathering without requiring access to the SCCM administration console GUI
        // Reference: https://github.com/Mayyhem/SharpSCCM/
        $string17 = /.{0,1000}SharpSCCM.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
