rule ScreenConnect
{
    meta:
        description = "Detection patterns for the tool 'ScreenConnect' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScreenConnect"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string1 = /\:8040\/SetupWizard\.aspx/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string2 = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\ScreenConnect\sClient\s\(/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string3 = /\\CurrentControlSet\\Services\\ScreenConnect\s/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string4 = /\\Documents\\ConnectWiseControl\\Files/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string5 = /\\InventoryApplicationFile\\screenconnect\.cl/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string6 = /\\InventoryApplicationFile\\screenconnect\.wi/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string7 = /\\ScreenConnect\sClient\s\(/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string8 = /\\ScreenConnect\.Client\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string9 = /\\ScreenConnect\.ClientService\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string10 = /\\ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string11 = /\\ScreenConnect\.Core\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string12 = /\\ScreenConnect\.InstallerActions\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string13 = /\\ScreenConnect\.Windows\.dll/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string14 = /\\ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string15 = /\\ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string16 = /\\ScreenConnect\\Bin\\/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string17 = /\\TEMP\\ScreenConnect\\.{0,1000}\.ps1/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string18 = /\\Temp\\ScreenConnect\\.{0,1000}\\setup\.msi/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string19 = /\\Windows\\Temp\\ScreenConnect\\.{0,1000}\.cmd/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string20 = /\\Windows\\Temp\\ScreenConnect\\.{0,1000}\.ps1/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string21 = /\<Data\>ScreenConnect\sSoftware\<\/Data\>/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string22 = /\<Provider\sName\=\'ScreenConnect\sSecurity\sManager\'\/\>/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string23 = /\<Provider\sName\=\'ScreenConnect\sWeb\sServer\'\/\>/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string24 = /cmd\.exe.{0,1000}\\TEMP\\ScreenConnect\\.{0,1000}\.cmd/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string25 = /https\:\/\/.{0,1000}\.screenconnect\.com\/Bin\/.{0,1000}\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string26 = /https\:\/\/.{0,1000}\.screenconnect\.com\/Host/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string27 = /https\:\/\/cloud\.screenconnect\.com\/\#\/trialtoinstance\?cookieValue\=/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string28 = /Program\sFiles\s\(x86\)\\ScreenConnect\sClient/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string29 = /\-relay\.screenconnect\.com/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string30 = /ScreenConnect\sSoftware/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string31 = /ScreenConnect\.Client\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string32 = /ScreenConnect\.Client\.exe\.jar/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string33 = /ScreenConnect\.ClientService\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string34 = /ScreenConnect\.ClientService\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string35 = /ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string36 = /SCREENCONNECT\.CLIENTSETUP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string37 = /ScreenConnect\.ClientUninstall\.vbs/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string38 = /ScreenConnect\.Core\.pdb/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string39 = /ScreenConnect\.Server\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string40 = /ScreenConnect\.Service\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string41 = /SCREENCONNECT\.SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string42 = /ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string43 = /SCREENCONNECT\.WINDOWSCLIENT\..{0,1000}\.pf/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string44 = /ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string45 = /ScreenConnect\.WindowsInstaller\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string46 = /ScreenConnect_.{0,1000}_Release\.msi/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string47 = /ScreenConnect_.{0,1000}_Release\.tar\.gz/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string48 = /ScreenConnect_.{0,1000}_Release\.zip/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string49 = /server.{0,1000}\-relay\.screenconnect\.com/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string50 = /\-web\.screenconnect\.com/ nocase ascii wide

    condition:
        any of them
}
