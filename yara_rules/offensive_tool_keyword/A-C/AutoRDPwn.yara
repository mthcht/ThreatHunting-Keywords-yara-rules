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
        $string1 = /\s\-Reverse\s\-IPAddress\s.*\s\-Port\s/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string2 = /\/AutoBypass\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string3 = /Add\-ServiceDacl/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string4 = /AutoBypass\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string5 = /AutoRDPwn/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string6 = /Bypass\-UAC/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string7 = /Chachi\-Enumerator\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string8 = /Chachi\-Enumerator\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string9 = /Check\-LocalAdminHash\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string10 = /DownloadAndExtractFromRemoteRegistry/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string11 = /Get\-CredPersist/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string12 = /Get\-DecodedPassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string13 = /Get\-DecryptedCpassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string14 = /Get\-DecryptedPassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string15 = /Get\-DiscosdurosGet\-PSDrive/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string16 = /Get\-LsaRunAsPPLStatus/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string17 = /Get\-NTLM\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string18 = /Get\-UnattendSensitiveData/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string19 = /Get\-UserPrivileges/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string20 = /Get\-Wlan\-Keys/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string21 = /Invoke\-ApplicationsOnStartupCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string22 = /Invoke\-CredentialFilesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string23 = /Invoke\-DllHijackingCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string24 = /Invoke\-GPPPasswordCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string25 = /Invoke\-HijackableDllsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string26 = /Invoke\-InstalledServicesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string27 = /Invoke\-Keylogger\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string28 = /Invoke\-LapsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string29 = /Invoke\-LocalAdminGroupCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string30 = /Invoke\-LsaProtectionsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string31 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string32 = /Invoke\-Phant0m/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string33 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string34 = /Invoke\-PipeShell\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string35 = /Invoke\-Portscan/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string36 = /Invoke\-Portscan\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string37 = /Invoke\-PowerShellTcp/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string38 = /Invoke\-PowerShellTcp\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string39 = /Invoke\-PrivescCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string40 = /Invoke\-PrivescCheck\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string41 = /Invoke\-PSexec\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string42 = /Invoke\-RDPwrap\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string43 = /Invoke\-RegistryAlwaysInstallElevatedCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string44 = /Invoke\-RevShellServer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string45 = /Invoke\-RunAs\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string46 = /Invoke\-SamBackupFilesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string47 = /Invoke\-ScheduledTasksCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string48 = /Invoke\-ServicesImagePermissionsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string49 = /Invoke\-ServicesPermissionsCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string50 = /Invoke\-ServicesPermissionsRegistryCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string51 = /Invoke\-ServicesUnquotedPathCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string52 = /Invoke\-SessionGopher/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string53 = /Invoke\-SharpRDP\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string54 = /Invoke\-SharpWeb\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string55 = /Invoke\-SMBExec/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string56 = /Invoke\-SMBExec\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string57 = /Invoke\-SystemStartupHistoryCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string58 = /Invoke\-UacCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string59 = /Invoke\-UnattendFilesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string60 = /Invoke\-UserPrivilegesCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string61 = /Invoke\-VaultCredCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string62 = /Invoke\-VNCServer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string63 = /Invoke\-VNCViewer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string64 = /Invoke\-WebRev\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string65 = /Invoke\-WinlogonCheck/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string66 = /Invoke\-WMIExec/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string67 = /ListAllUsers\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string68 = /PortScan\-Alive/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string69 = /Portscan\-Port/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string70 = /RDP\-Caching\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string71 = /Resources\/Design\/NinjaStyle\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string72 = /Search\-cpassword/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string73 = /SessionGopher\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string74 = /Sherlock\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string75 = /Start\-WebServer\.ps1/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string76 = /Test\-DllExists/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string77 = /Test\-ServiceDaclPermission/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string78 = /Write\-PortscanOut/ nocase ascii wide

    condition:
        any of them
}