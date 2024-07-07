rule teamviewer
{
    meta:
        description = "Detection patterns for the tool 'teamviewer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamviewer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string1 = /\.exe\s\-\-IPCport\s5939\s\-\-Module\s1/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string2 = /\.router\.teamviewer\.com/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string3 = /\/Create\s\/TN\sTVInstallRestore\s\/TR\s/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string4 = /\\AppData\\Roaming\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string5 = /\\CurrentControlSet\\Services\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string6 = /\\Program\sFiles\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string7 = /\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string8 = /\\Software\\TeamViewer\\Temp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string9 = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string10 = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string11 = /\\TeamViewer\\Connections\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string12 = /\\TeamViewer\\Connections_incoming\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string13 = /\\TeamViewer_\.ex/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string14 = /\\teamviewer_note\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string15 = /\\TeamViewerSession\\shell\\open/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string16 = /\\TeamViewerTermsOfUseAccepted/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string17 = /\\TV15Install\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string18 = /\\TVExtractTemp\\TeamViewer_Resource_/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string19 = /\\TVExtractTemp\\tvfiles\.7z/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string20 = /\\TvGetVersion\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string21 = /\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string22 = /\\TVWebRTC\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string23 = /\\Users\\Public\\Desktop\\TVTest\.tmp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string24 = /\\Windows\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string25 = /AppData\\Local\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string26 = /AppData\\Roaming\\Microsoft\\Windows\\SendTo\\TeamViewer\.lnk/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string27 = /client\.teamviewer\.com/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string28 = /download\.teamviewer\.com\.cdn\.cloudflare\.net/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string29 = /HKLM\\SOFTWARE\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string30 = /MRU\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string31 = /TeamViewer\sVPN\sAdapter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string32 = /TEAMVIEWER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string33 = /TeamViewer\\tv_w32\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string34 = /TeamViewer\\tv_x64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string35 = /TeamViewer\\tv_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string36 = /TeamViewer\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string37 = /TEAMVIEWER_\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string38 = /TeamViewer_Desktop\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string39 = /TEAMVIEWER_DESKTOP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string40 = /TeamViewer_Hooks\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string41 = /TeamViewer_Service\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string42 = /TEAMVIEWER_SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string43 = /TeamViewer_Setup_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string44 = /TEAMVIEWER_SETUP_X64\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string45 = /TeamViewer_VirtualDeviceDriver/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string46 = /TeamViewer_XPSDriverFilter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string47 = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string48 = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string49 = /TeamViewerMeetingAddIn\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string50 = /TeamViewerMeetingAddinShim\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string51 = /TeamViewerMeetingAddinShim64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string52 = /teamviewervpn\.sys/ nocase ascii wide

    condition:
        any of them
}
