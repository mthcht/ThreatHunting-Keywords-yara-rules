rule PowerSploit
{
    meta:
        description = "Detection patterns for the tool 'PowerSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string1 = /.{0,1000}\/avred\.py.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string2 = /.{0,1000}\\avred\.py.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string3 = /.{0,1000}\\DllVoidFunction\.txt.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string4 = /.{0,1000}\\local_admins\.csv.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string5 = /.{0,1000}\\Mayhem\.psm1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string6 = /.{0,1000}\\powerup\.exe.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string7 = /.{0,1000}\\PowerUp\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string8 = /.{0,1000}\\Recon\.tests\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string9 = /.{0,1000}Add\-Persistence\s.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string10 = /.{0,1000}Add\-ServiceDacl\s.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string11 = /.{0,1000}AntivirusBypass\.psm1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string12 = /.{0,1000}Convert\-NT4toCanonical.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string13 = /.{0,1000}EvilPayload\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string14 = /.{0,1000}ExeToInjectInTo\..{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string15 = /.{0,1000}Exfiltration\.tests\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string16 = /.{0,1000}Find\-AVSignature.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string17 = /.{0,1000}Find\-GPOComputerAdmin.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string18 = /.{0,1000}Find\-InterestingFile.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string19 = /.{0,1000}Find\-LocalAdminAccess.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string20 = /.{0,1000}Find\-PathDLLHijack.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string21 = /.{0,1000}Find\-ProcessDLLHijack.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string22 = /.{0,1000}Get\-CachedRDPConnection.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string23 = /.{0,1000}Get\-DFSshare.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string24 = /.{0,1000}Get\-ExploitableSystem.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string25 = /.{0,1000}Get\-GPPPassword.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string26 = /.{0,1000}Get\-Keystrokes\s.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string27 = /.{0,1000}Get\-Keystrokes.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string28 = /.{0,1000}Get\-LastLoggedOn.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string29 = /.{0,1000}Get\-ModifiableRegistryAutoRun.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string30 = /.{0,1000}Get\-ModifiableScheduledTaskFile.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string31 = /.{0,1000}Get\-ModifiableService.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string32 = /.{0,1000}Get\-NetDomainController.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string33 = /.{0,1000}Get\-NetDomainTrust.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string34 = /.{0,1000}Get\-NetFileServer.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string35 = /.{0,1000}Get\-NetGPOGroup.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string36 = /.{0,1000}Get\-NetLocalGroup.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string37 = /.{0,1000}Get\-NetLoggedon.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string38 = /.{0,1000}Get\-NetRDPSession.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string39 = /.{0,1000}Get\-RegistryAlwaysInstallElevated.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string40 = /.{0,1000}Get\-VaultCredential.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string41 = /.{0,1000}Get\-VolumeShadowCopy.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string42 = /.{0,1000}Invoke\-ACLScanner.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string43 = /.{0,1000}Invoke\-CheckLocalAdminAccess.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string44 = /.{0,1000}Invoke\-CredentialInjection.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string45 = /.{0,1000}Invoke\-CredentialInjection\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string46 = /.{0,1000}Invoke\-CredentialInjection\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string47 = /.{0,1000}Invoke\-DllInjection.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string48 = /.{0,1000}Invoke\-EnumerateLocalAdmin.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string49 = /.{0,1000}Invoke\-EventHunter.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string50 = /.{0,1000}Invoke\-FileFinder.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string51 = /.{0,1000}Invoke\-MapDomainTrust.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string52 = /.{0,1000}Invoke\-Mimikatz.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string53 = /.{0,1000}Invoke\-NinjaCopy.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string54 = /.{0,1000}Invoke\-Portscan.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string55 = /.{0,1000}Invoke\-PrivescAudit.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string56 = /.{0,1000}Invoke\-ProcessHunter.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string57 = /.{0,1000}Invoke\-ReflectivePEInjection.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string58 = /.{0,1000}Invoke\-ServiceAbuse.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string59 = /.{0,1000}Invoke\-ShareFinder.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string60 = /.{0,1000}Invoke\-Shellcode.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string61 = /.{0,1000}Invoke\-Shellcode\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string62 = /.{0,1000}Invoke\-TokenManipulation.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string63 = /.{0,1000}Invoke\-UserHunter.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string64 = /.{0,1000}Invoke\-WmiCommand\s.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string65 = /.{0,1000}Mount\-VolumeShadowCopy.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string66 = /.{0,1000}Naughty\-Script\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string67 = /.{0,1000}New\-ElevatedPersistenceOption.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string68 = /.{0,1000}New\-UserPersistenceOption.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string69 = /.{0,1000}New\-VolumeShadowCopy.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string70 = /.{0,1000}Persistence\.psm1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string71 = /.{0,1000}PowerShell_PoC\.zip.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string72 = /.{0,1000}PowerSploit\..{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string73 = /.{0,1000}Privesc\.psm1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string74 = /.{0,1000}Privesc\.tests\.ps1.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string75 = /.{0,1000}Remove\-VolumeShadowCopy.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string76 = /.{0,1000}RevertToSelf\swas\ssuccessful.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string77 = /.{0,1000}Test\-ServiceDaclPermission.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string78 = /.{0,1000}Write\-HijackDll.{0,1000}/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string79 = /.{0,1000}Write\-UserAddMSI.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
