rule UltraVNC
{
    meta:
        description = "Detection patterns for the tool 'UltraVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UltraVNC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string1 = " start uvnc_service" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string2 = " stop uvnc_service" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string3 = /\sultravnc\.ini\s/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string4 = /\svnc\.ini\s/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string5 = "\"publisher\":\"uvnc bvba" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string6 = /\/downloads\/ultravnc\.html/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string7 = /\\127\.0\.0\.1\-5900\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string8 = /\\AppData\\Roaming\\.{0,1000}\-5900\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string9 = /\\AppData\\Roaming\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string10 = /\\createpassword\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string11 = /\\CurrentVersion\\Uninstall\\Ultravnc2_is1\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string12 = /\\InventoryApplicationFile\\ultravnc_/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string13 = /\\options\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string14 = /\\Program\sFiles\s\(x86\)\\uvnc\sbvba\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string15 = /\\Services\\EventLog\\Application\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string16 = /\\SOFTWARE\\ORL\\VNCHooks\\Application_Prefs\\WinVNC/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string17 = /\\ultravnc\.cer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string18 = /\\UltraVNC\.ini/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string19 = /\\uvnc\sbvba\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string20 = /\\uvnc_launch\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string21 = /\\uvnc_settings\.ex/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string22 = /\\uvnc_settings\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string23 = /\\uvnckeyboardhelper\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string24 = /\\vncviewer\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string25 = /\\winvnc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string26 = /\\winvncsc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string27 = /\\winwvc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string28 = /bvba_UltraVNC_.{0,1000}_exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string29 = /certutil\.exe.{0,1000}\s\-addstore\s\\"TrustedPublisher\\".{0,1000}ultravnc\.cer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string30 = "'Company'>UltraVNC</Data>" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string31 = "'Description'>VNC server</Data>" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string32 = /firewall\sadd\sallowedprogram\s.{0,1000}vncviewer\.exe.{0,1000}\sENABLE\sALL/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string33 = /firewall\sadd\sallowedprogram\s.{0,1000}winvnc\.exe.{0,1000}\sENABLE\sALL/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string34 = "firewall add portopening TCP 5800 vnc5800" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string35 = "firewall add portopening TCP 5900 vnc5900" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string36 = /HKCR\\\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string37 = /Program\sFiles\s\(x86\)\\uvnc\sbvba\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string38 = /UltraVNC\sLauncher\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string39 = "ultravnc mslogonacl" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string40 = /UltraVNC\sRepeater\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string41 = /UltraVNC\sServer\sSettings\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string42 = /UltraVNC\sServer\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string43 = "ultravnc testauth" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string44 = /UltraVNC\sViewer\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string45 = /UltraVNC_.{0,1000}_X86_Setup/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string46 = /ULTRAVNC_1.{0,1000}_X86_SETUP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string47 = "ultravnc_repeater" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string48 = "ultravnc_server" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string49 = "ultravnc_viewer" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string50 = "VNCviewer Config File" nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string51 = /VncViewer\.Config/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string52 = /VNCVIEWER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string53 = /WinVNC\.exe/ nocase ascii wide

    condition:
        any of them
}
