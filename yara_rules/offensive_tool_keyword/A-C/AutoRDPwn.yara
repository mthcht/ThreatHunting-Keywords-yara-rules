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
        $string1 = /.{0,1000}\s\-Reverse\s\-IPAddress\s.{0,1000}\s\-Port\s.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string2 = /.{0,1000}\/AutoBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string3 = /.{0,1000}Add\-ServiceDacl.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string4 = /.{0,1000}AutoBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string5 = /.{0,1000}AutoRDPwn.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string6 = /.{0,1000}Bypass\-UAC.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string7 = /.{0,1000}Chachi\-Enumerator\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string8 = /.{0,1000}Chachi\-Enumerator\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string9 = /.{0,1000}Check\-LocalAdminHash\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string10 = /.{0,1000}DownloadAndExtractFromRemoteRegistry.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string11 = /.{0,1000}Get\-CredPersist.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string12 = /.{0,1000}Get\-DecodedPassword.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string13 = /.{0,1000}Get\-DecryptedCpassword.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string14 = /.{0,1000}Get\-DecryptedPassword.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string15 = /.{0,1000}Get\-DiscosdurosGet\-PSDrive.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string16 = /.{0,1000}Get\-LsaRunAsPPLStatus.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string17 = /.{0,1000}Get\-NTLM\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string18 = /.{0,1000}Get\-UnattendSensitiveData.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string19 = /.{0,1000}Get\-UserPrivileges.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string20 = /.{0,1000}Get\-Wlan\-Keys.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string21 = /.{0,1000}Invoke\-ApplicationsOnStartupCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string22 = /.{0,1000}Invoke\-CredentialFilesCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string23 = /.{0,1000}Invoke\-DllHijackingCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string24 = /.{0,1000}Invoke\-GPPPasswordCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string25 = /.{0,1000}Invoke\-HijackableDllsCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string26 = /.{0,1000}Invoke\-InstalledServicesCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string27 = /.{0,1000}Invoke\-Keylogger\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string28 = /.{0,1000}Invoke\-LapsCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string29 = /.{0,1000}Invoke\-LocalAdminGroupCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string30 = /.{0,1000}Invoke\-LsaProtectionsCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string31 = /.{0,1000}Invoke\-Mimikatz\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string32 = /.{0,1000}Invoke\-Phant0m.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string33 = /.{0,1000}Invoke\-Phant0m\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string34 = /.{0,1000}Invoke\-PipeShell\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string35 = /.{0,1000}Invoke\-Portscan.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string36 = /.{0,1000}Invoke\-Portscan\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string37 = /.{0,1000}Invoke\-PowerShellTcp.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string38 = /.{0,1000}Invoke\-PowerShellTcp\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string39 = /.{0,1000}Invoke\-PrivescCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string40 = /.{0,1000}Invoke\-PrivescCheck\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string41 = /.{0,1000}Invoke\-PSexec\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string42 = /.{0,1000}Invoke\-RDPwrap\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string43 = /.{0,1000}Invoke\-RegistryAlwaysInstallElevatedCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string44 = /.{0,1000}Invoke\-RevShellServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string45 = /.{0,1000}Invoke\-RunAs\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string46 = /.{0,1000}Invoke\-SamBackupFilesCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string47 = /.{0,1000}Invoke\-ScheduledTasksCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string48 = /.{0,1000}Invoke\-ServicesImagePermissionsCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string49 = /.{0,1000}Invoke\-ServicesPermissionsCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string50 = /.{0,1000}Invoke\-ServicesPermissionsRegistryCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string51 = /.{0,1000}Invoke\-ServicesUnquotedPathCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string52 = /.{0,1000}Invoke\-SessionGopher.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string53 = /.{0,1000}Invoke\-SharpRDP\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string54 = /.{0,1000}Invoke\-SharpWeb\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string55 = /.{0,1000}Invoke\-SMBExec.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string56 = /.{0,1000}Invoke\-SMBExec\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string57 = /.{0,1000}Invoke\-SystemStartupHistoryCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string58 = /.{0,1000}Invoke\-UacCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string59 = /.{0,1000}Invoke\-UnattendFilesCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string60 = /.{0,1000}Invoke\-UserPrivilegesCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string61 = /.{0,1000}Invoke\-VaultCredCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string62 = /.{0,1000}Invoke\-VNCServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string63 = /.{0,1000}Invoke\-VNCViewer\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string64 = /.{0,1000}Invoke\-WebRev\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string65 = /.{0,1000}Invoke\-WinlogonCheck.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string66 = /.{0,1000}Invoke\-WMIExec.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string67 = /.{0,1000}ListAllUsers\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string68 = /.{0,1000}PortScan\-Alive.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string69 = /.{0,1000}Portscan\-Port.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string70 = /.{0,1000}RDP\-Caching\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string71 = /.{0,1000}Resources\/Design\/NinjaStyle\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string72 = /.{0,1000}Search\-cpassword.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string73 = /.{0,1000}SessionGopher\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string74 = /.{0,1000}Sherlock\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string75 = /.{0,1000}Start\-WebServer\.ps1.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string76 = /.{0,1000}Test\-DllExists.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string77 = /.{0,1000}Test\-ServiceDaclPermission.{0,1000}/ nocase ascii wide
        // Description: AutoRDPwn is a post-exploitation framework created in Powershell designed primarily to automate the Shadow attack on Microsoft Windows computers
        // Reference: https://github.com/JoelGMSec/AutoRDPwn
        $string78 = /.{0,1000}Write\-PortscanOut.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
