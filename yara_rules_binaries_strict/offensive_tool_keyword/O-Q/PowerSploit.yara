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
        $string1 = /\s\-CheckShareAccess\s\-Verbose/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string2 = /\/avred\.py/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string3 = /\/Sharefinder\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string4 = /\\avred\.py/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string5 = /\\DllVoidFunction\.txt/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string6 = /\\local_admins\.csv/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string7 = /\\Mayhem\.psm1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string8 = /\\PowerSploit/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string9 = /\\powerup\.exe/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string10 = /\\PowerUp\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string11 = /\\ProgramData\\shares\.txt/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string12 = /\\Recon\.tests\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string13 = /\\Sharefinder\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string14 = /6CAFC0C6\-A428\-4D30\-A9F9\-700E829FEA51/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string15 = /Add\-Persistence\s/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string16 = /Add\-ServiceDacl\s/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string17 = /AntivirusBypass\.psm1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string18 = /Convert\-NT4toCanonical/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string19 = /EvilPayload\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string20 = /ExeToInjectInTo\./ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string21 = /Exfiltration\.tests\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string22 = /Find\-AVSignature/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string23 = /Find\-GPOComputerAdmin/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string24 = /Find\-InterestingFile/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string25 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string26 = /Find\-PathDLLHijack/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string27 = /Find\-ProcessDLLHijack/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string28 = /Get\-CachedRDPConnection/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string29 = /Get\-DFSshare/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string30 = /Get\-ExploitableSystem/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string31 = /Get\-GPPAutologon\s/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string32 = /Get\-GPPAutologon\./ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string33 = /Get\-GPPPassword/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string34 = /Get\-Keystrokes\s/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string35 = /Get\-Keystrokes/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string36 = /Get\-LastLoggedOn/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string37 = /Get\-ModifiableRegistryAutoRun/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string38 = /Get\-ModifiableScheduledTaskFile/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string39 = /Get\-ModifiableService/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string40 = /Get\-NetDomainController/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string41 = /Get\-NetDomainTrust/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string42 = /Get\-NetFileServer/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string43 = /Get\-NetGPO\s\-UserIdentity\s/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string44 = /Get\-NetGPOGroup/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string45 = /Get\-NetLocalGroup/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string46 = /Get\-NetLoggedon/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string47 = /Get\-NetRDPSession/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string48 = /Get\-RegistryAlwaysInstallElevated/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string49 = /Get\-VaultCredential/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string50 = /Get\-VolumeShadowCopy/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string51 = /Invoke\-ACLScanner/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string52 = /Invoke\-CheckLocalAdminAccess/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string53 = /Invoke\-CredentialInjection/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string54 = /Invoke\-CredentialInjection\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string55 = /Invoke\-CredentialInjection\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string56 = /Invoke\-DllInjection/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string57 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string58 = /Invoke\-EventHunter/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string59 = /Invoke\-FileFinder/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string60 = /Invoke\-MapDomainTrust/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string61 = /Invoke\-Mimikatz/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string62 = /Invoke\-NinjaCopy/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string63 = /Invoke\-Portscan/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string64 = /Invoke\-PrivescAudit/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string65 = /Invoke\-ProcessHunter/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string66 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string67 = /Invoke\-ServiceAbuse/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string68 = /Invoke\-ShareFinder/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string69 = /Invoke\-Shellcode/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string70 = /Invoke\-Shellcode\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string71 = /Invoke\-TokenManipulation/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string72 = /Invoke\-UserHunter/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string73 = /Invoke\-WmiCommand\s/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string74 = /Mount\-VolumeShadowCopy/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string75 = /Naughty\-Script\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string76 = /New\-ElevatedPersistenceOption/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string77 = /New\-UserPersistenceOption/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string78 = /New\-VolumeShadowCopy/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string79 = /Persistence\.psm1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string80 = /PowerShell_PoC\.zip/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string81 = /PowerShellMafia\/PowerSploit/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string82 = /PowerSploit/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string83 = /PowerSploit\-.{0,100}\.zip/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string84 = /PowerSploit\./ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string85 = /PowerSploit\/releases/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string86 = /Privesc\.psm1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string87 = /Privesc\.tests\.ps1/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string88 = /Remove\-VolumeShadowCopy/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string89 = /RevertToSelf\swas\ssuccessful/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string90 = /Test\-ServiceDaclPermission/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string91 = /Write\-HijackDll/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string92 = /Write\-UserAddMSI/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
