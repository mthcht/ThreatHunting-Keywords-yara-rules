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
        $string1 = /HKLM\\SOFTWARE\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string2 = /download\.teamviewer\.com\.cdn\.cloudflare\.net/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string3 = /client\.teamviewer\.com/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string4 = /\\TeamViewer_Service\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string5 = /\\Program\sFiles\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string6 = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string7 = /TeamViewer\sVPN\sAdapter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string8 = /TeamViewerMeetingAddinShim64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string9 = /TeamViewerMeetingAddIn\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string10 = /TeamViewerMeetingAddinShim\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string11 = /\\TvGetVersion\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string12 = /TeamViewer\\tv_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string13 = /TeamViewer\\tv_x64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string14 = /TeamViewer_Hooks\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string15 = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string16 = /TEAMVIEWER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string17 = /TEAMVIEWER_\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string18 = /TEAMVIEWER_DESKTOP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string19 = /TEAMVIEWER_SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string20 = /TEAMVIEWER_SETUP_X64\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string21 = /\\Windows\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string22 = /\\AppData\\Roaming\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string23 = /\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string24 = /\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string25 = /TeamViewer_XPSDriverFilter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string26 = /\\TVWebRTC\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string27 = /TeamViewer_Setup_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string28 = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string29 = /\\TeamViewerTermsOfUseAccepted/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string30 = /\\CurrentControlSet\\Services\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string31 = /TeamViewer_Desktop\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string32 = /TeamViewer\\tv_w32\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string33 = /\\Software\\TeamViewer\\Temp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string34 = /\\teamviewer_note\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string35 = /TeamViewer_VirtualDeviceDriver/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string36 = /\\TeamViewerSession\\shell\\open/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string37 = /TeamViewer\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string38 = /\\TVExtractTemp\\TeamViewer_Resource_/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string39 = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string40 = /AppData\\Local\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string41 = /\\TV15Install\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string42 = /teamviewervpn\.sys/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string43 = /AppData\\Roaming\\Microsoft\\Windows\\SendTo\\TeamViewer\.lnk/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string44 = /MRU\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string45 = /\\TeamViewer\\Connections\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string46 = /\\Users\\Public\\Desktop\\TVTest\.tmp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string47 = /\\TeamViewer_\.ex/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string48 = /\\TVExtractTemp\\tvfiles\.7z/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string49 = /\\TeamViewer\\Connections_incoming\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string50 = /\.router\.teamviewer\.com/ nocase ascii wide

    condition:
        any of them
}
