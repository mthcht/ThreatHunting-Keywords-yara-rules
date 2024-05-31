rule AutoRDPwn
{
    meta:
        description = "Detection patterns for the tool 'AutoRDPwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoRDPwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string1 = /\s\-Reverse\s\-IPAddress\s.{0,1000}\s\-Port\s/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string2 = /\s\-TaskName\s.{0,1000}AutoRDPwn/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string3 = /\/AutoBypass\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string4 = /\/autordpwn\.php/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string5 = /\/AutoRDPwn\/master\// nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string6 = /656761faa342911d398af21edaf085f978ffa53a6bf3919763dfa82aba2301f1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string7 = /86c1800ab9c9f90d5d5ce81a1f1daae1446cdb98686c59b4d5336216725bfb8e/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string8 = /97b8d3a33ca3a06d24553a8ea8a5a89520ebe15655fa338b2f7c7c8883ae38da/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string9 = /Add\-ServiceDacl/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string10 = /AutoBypass\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string11 = /AutoRDPwn/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string12 = /AutoRDPwn\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string13 = /Bypass\-UAC/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string14 = /c7874c257949a3c09dcb16f17c6fdb5ea0c5adb143004e7cc4adc63eb3ed785c/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string15 = /Chachi\-Enumerator\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string16 = /Check\-LocalAdminHash\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string17 = /d366383b6e737fd3af2acc5ebc9f209a2c49209b7b444af3c7fe1d39e1775894/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string18 = /DownloadAndExtractFromRemoteRegistry/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string19 = /Get\-CredPersist/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string20 = /Get\-DecodedPassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string21 = /Get\-DecryptedCpassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string22 = /Get\-DecryptedPassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string23 = /Get\-DiscosdurosGet\-PSDrive/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string24 = /Get\-LsaRunAsPPLStatus/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string25 = /Get\-NTLM\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string26 = /Get\-UnattendSensitiveData/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string27 = /Get\-UserPrivileges/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string28 = /Get\-Wlan\-Keys/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string29 = /Invoke\-ApplicationsOnStartupCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string30 = /Invoke\-CredentialFilesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string31 = /Invoke\-DllHijackingCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string32 = /Invoke\-GPPPasswordCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string33 = /Invoke\-HijackableDllsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string34 = /Invoke\-InstalledServicesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string35 = /Invoke\-Keylogger/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string36 = /Invoke\-LapsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string37 = /Invoke\-LocalAdminGroupCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string38 = /Invoke\-LsaProtectionsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string39 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string40 = /Invoke\-Phant0m/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string41 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string42 = /Invoke\-PipeShell\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string43 = /Invoke\-Portscan/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string44 = /Invoke\-Portscan\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string45 = /Invoke\-PowerShellTcp/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string46 = /Invoke\-PowerShellTcp\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string47 = /Invoke\-PrivescCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string48 = /Invoke\-PrivescCheck\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string49 = /Invoke\-PSexec\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string50 = /Invoke\-RDPwrap\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string51 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string52 = /Invoke\-RevShellServer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string53 = /Invoke\-RunAs\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string54 = /Invoke\-SamBackupFilesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string55 = /Invoke\-ScheduledTasksCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string56 = /Invoke\-ServicesImagePermissionsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string57 = /Invoke\-ServicesPermissionsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string58 = /Invoke\-ServicesPermissionsRegistryCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string59 = /Invoke\-ServicesUnquotedPathCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string60 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string61 = /Invoke\-SharpRDP\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string62 = /Invoke\-SharpWeb\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string63 = /Invoke\-SMBExec/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string64 = /Invoke\-SMBExec\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string65 = /Invoke\-SystemStartupHistoryCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string66 = /Invoke\-UacCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string67 = /Invoke\-UnattendFilesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string68 = /Invoke\-UserPrivilegesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string69 = /Invoke\-VaultCredCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string70 = /Invoke\-VNCServer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string71 = /Invoke\-VNCViewer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string72 = /Invoke\-WebRev\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string73 = /Invoke\-WinlogonCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string74 = /Invoke\-WMIExec/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string75 = /ListAllUsers\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string76 = /net\slocalgroup\s.{0,1000}\sAutoRDPwn\s\/add/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string77 = /net\suser\sAutoRDPwn/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string78 = /PortScan\-Alive/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string79 = /Portscan\-Port/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string80 = /RDP\-Caching\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string81 = /Resources\/Design\/NinjaStyle\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string82 = /Search\-cpassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string83 = /SessionGopher\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string84 = /Set\-Content\s\-Path\spsexec\.exe/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string85 = /Set\-Content\s\-Path\sserver\.exe/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string86 = /Set\-Content\s\-Path\sSharpRDP\.exe/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string87 = /Set\-Content\s\-Path\sSharpWeb\.exe/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string88 = /Sherlock\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string89 = /Start\-WebServer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string90 = /Test\-DllExists/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string91 = /Test\-ServiceDaclPermission/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string92 = /VNCViewer\.exe\s\/password\sAutoRDPwn\s/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string93 = /Write\-PortscanOut/ nocase ascii wide

    condition:
        any of them
}
