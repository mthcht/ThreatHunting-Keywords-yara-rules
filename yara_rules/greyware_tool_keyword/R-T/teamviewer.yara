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
        $string1 = /\.router\.teamviewer\.com/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string2 = /\/Create\s\/TN\sTVInstallRestore\s\/TR\s/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string3 = /\\AppData\\Roaming\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string4 = /\\CurrentControlSet\\Services\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string5 = /\\Program\sFiles\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string6 = /\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string7 = /\\Software\\TeamViewer\\Temp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string8 = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string9 = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string10 = /\\TeamViewer\\Connections\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string11 = /\\TeamViewer\\Connections_incoming\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string12 = /\\TeamViewer_\.ex/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string13 = /\\teamviewer_note\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string14 = /\\TeamViewerSession\\shell\\open/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string15 = /\\TeamViewerTermsOfUseAccepted/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string16 = /\\TV15Install\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string17 = /\\TVExtractTemp\\TeamViewer_Resource_/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string18 = /\\TVExtractTemp\\tvfiles\.7z/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string19 = /\\TvGetVersion\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string20 = /\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string21 = /\\TVWebRTC\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string22 = /\\Users\\Public\\Desktop\\TVTest\.tmp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string23 = /\\Windows\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string24 = /AppData\\Local\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string25 = /AppData\\Roaming\\Microsoft\\Windows\\SendTo\\TeamViewer\.lnk/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string26 = /client\.teamviewer\.com/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string27 = /download\.teamviewer\.com\.cdn\.cloudflare\.net/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string28 = /HKLM\\SOFTWARE\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string29 = /MRU\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string30 = /TeamViewer\sVPN\sAdapter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string31 = /TEAMVIEWER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string32 = /TeamViewer\\tv_w32\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string33 = /TeamViewer\\tv_x64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string34 = /TeamViewer\\tv_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string35 = /TeamViewer\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string36 = /TEAMVIEWER_\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string37 = /TeamViewer_Desktop\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string38 = /TEAMVIEWER_DESKTOP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string39 = /TeamViewer_Hooks\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string40 = /TeamViewer_Service\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string41 = /TEAMVIEWER_SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string42 = /TeamViewer_Setup_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string43 = /TEAMVIEWER_SETUP_X64\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string44 = /TeamViewer_VirtualDeviceDriver/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string45 = /TeamViewer_XPSDriverFilter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string46 = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string47 = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string48 = /TeamViewerMeetingAddIn\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string49 = /TeamViewerMeetingAddinShim\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string50 = /TeamViewerMeetingAddinShim64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string51 = /teamviewervpn\.sys/ nocase ascii wide

    condition:
        any of them
}
