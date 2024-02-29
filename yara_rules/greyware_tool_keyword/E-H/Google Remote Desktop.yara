rule Google_Remote_Desktop
{
    meta:
        description = "Detection patterns for the tool 'Google Remote Desktop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Google Remote Desktop"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string1 = /\schrome\-remote\-desktop\@/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string2 = /\.chrome\-remote\-desktop\-session/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string3 = /\/system\/chrome\-remote\-desktop\@/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string4 = /\\Chrome\sRemote\sDesktop\\host\.json/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string5 = /\\Google\\Chrome\sRemote\sDesktop\\/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string6 = /\\pipe\\chrome_remote_desktop/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string7 = /\\remote_assistance_host\.exe/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string8 = /\\remoting_desktop\.exe/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string9 = /\\remoting_host\.exe/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string10 = /\\remoting_native_messaging_host\.exe/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string11 = /\\remoting_start_host\.exe/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string12 = /\<Data\>Product\:\sChrome\sRemote\sDesktop\sHost/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string13 = /\<Provider\sName\=\"chromoting\"\s\/\>/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string14 = /Channel\sIP\sfor\sclient\:\s.{0,1000}\@gmail\.com\/chromoting/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string15 = /Chrome\sremote\sdesktop\sinstallation\scompleted/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string16 = /chrome\-remote\-desktop\.service/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string17 = /chrome\-remote\-desktop_current_amd64\.deb/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string18 = /chromeremotedesktophost\.msi/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string19 = /export\sCHROME_REMOTE_DESKTOP_DEFAULT_DESKTOP_SIZES/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string20 = /\-Force\sStop\-Process\s\-Name\sremote_webauthn/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string21 = /google\-chrome\-stable_current_amd64\.deb/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string22 = /https\:\/\/remotedesktop\.google\.com\/_\/oauthredirect/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string23 = /https\:\/\/remotedesktop\.google\.com\/headless/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string24 = /inomeogfingihgjfjlpeplalcfajhgai/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string25 = /remotedesktop\.google\.com\/access/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string26 = /remotedesktop\.google\.com\/support/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string27 = /Stop\-Process\s\-Force\s\-Name\sremote_assistance_host/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string28 = /Stop\-Process\s\-Force\s\-Name\sremote_assistance_host_uiaccess/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string29 = /Stop\-Process\s\-Force\s\-Name\sremoting_native_messaging_host/ nocase ascii wide
        // Description: Google Remote Desktop to access remote computers - abused by attackers
        // Reference: https://remotedesktop.google.com
        $string30 = /SYSLOG_IDENTIFIER\=chrome\-remote\-desktop/ nocase ascii wide

    condition:
        any of them
}
