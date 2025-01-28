rule PSAttack
{
    meta:
        description = "Detection patterns for the tool 'PSAttack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAttack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string1 = /\/PSAttack\.git/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string2 = /\/PSAttack\.zip/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string3 = "/PSAttack/releases/download/" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string4 = /\\attackState\.cmd/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string5 = /\\DNS\-TXT\-Pwnage\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string6 = /\\Do\-Exfiltration\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string7 = /\\get\-attack\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string8 = /\\Get\-GPPPassword\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string9 = /\\Get\-WLAN\-Keys\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string10 = /\\Gupt\-Backdoor\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string11 = /\\Inveigh\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string12 = /\\Invoke\-MS16\-032\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string13 = /\\Invoke\-PsUACme\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string14 = /\\Powercat\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string15 = /\\PowerUp\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string16 = /\\PSAttack\.sln/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string17 = /\\PSAttack\.zip/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string18 = "06e22309431bcbf87df30bb1b6e971b0edfe05f7f466f87e9c9982c3e4715bc5" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string19 = "0d4ab1674ad2b13652979d996a41f55a353eb2f32f854a95c7068e66c072f63c" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string20 = "1316ca67af20db4bc3b47218855dfd47d9075f0a72bb681821f70af4fdce6f5c" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string21 = "17893a44c856de700187251711368a3393fa79c92b65d39eb6eb56718a78c255" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string22 = "1d70076be53e454fdb7dda0570961920e6bfe2d11ab0080064e206dd20c83333" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string23 = "1e8fc1ed166a78bcb9075d3cd122af35d3bcca902a842bde00a0c6d515820cfa" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string24 = "2103fd114d530753c7eadd8561d76ed952863c9d58a64ecf6b3abb160f863db1" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string25 = "3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string26 = "4621d400f556301fd9ba40c1325a65727b4eb564eeda5fb0368f547eec603ff3" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string27 = "4b8997973189f7f85b4c2ad8fd3320269481d70b70c67046d0994844e5fb852a" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string28 = "565d4502e4f8d24a2bf76a7cffdf27b54604b8211c3986ae05fa75bb46d8b356" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string29 = "5e77fa12d0f1b9a4a7249a6a496f8236552bc0adcbe818d9e997e1ca68819224" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string30 = "830023999e063bef7fd09709d0aa3e34eb0cce2dacd382f381350e8890b20dee" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string31 = "89d37b998b4dde0492d237508a2521a79768d284f8d184a017fcbe444393307c" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string32 = "8cOpc1mnZbcpRkvRwqE8jeEvQdxxO67SVM6GP8rLbDdePzAzLVTbI23DCQCaMIgo" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string33 = "929cc2194f0dff4b6b8e7102e841253dfbdca6790f45e0f1165fbdbeeffc390a" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string34 = "a75c79d0fbcc1c76214625d2924fa60e2c74bf8b4b40bf191a1f68a4b28e748d" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string35 = "a834a0a0c5e0d0ef14de2e986b53b032747f52071815957e42633495fb7bc42f" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string36 = "ae18dc1b4124abbbd1eaff296cedaa2e8d6ef2ad1070b537f1963355cd1cd769" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string37 = "c664a81f5833fc705151ebee4e25084e6a2c7315ad1324245460aaae5ed9d065" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string38 = "c6e3cbe978095e155f6fafe6028c2f6a0a6e156a46d3473fb795c701ead2fd0b" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string39 = /ConvertFrom\-CSV\s\$attacksCSV/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string40 = /Could\snot\srun\sAMSI\sbypass\./ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string41 = "d1d533085ee36aee9b817636d6ed5323da22461af7de88b016484610531c6f0e" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string42 = "DA1B7904-0DDC-45A0-875F-33BBA2236C44" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string43 = "e06104b2d8e8ba207a916352e2f49e4d03f6b0c3bb04d5703e71037ff279ec4d" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string44 = "e8bba4503b2e26b62002980969dc7a3d1dbe1699c4ce054929692704600b33ba" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string45 = "e94cb3644275a5675abf5146e368ec04147570db966781014bf320c921ccbfd2" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string46 = "ecf242b41a845439cc80e76710718b3162be13aee4c7abfa153a5e913c0f4767" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string47 = "f2935c9643fbbf76da73f5218cf6a8b299b4252247d81060f8d7d12f146bd69d" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string48 = "GDSSecurity/PSAttack" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string49 = "Get-Attack -term " nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string50 = /Invoke\-MetasploitPayload\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string51 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string52 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string53 = /Invoke\-mimikittenz\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string54 = /Invoke\-MS16\-032\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string55 = "Invoke-NinjaCopy" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string56 = /Invoke\-PsUACme\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string57 = /Invoke\-Shellcode\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string58 = /Invoke\-WMICommand\.ps1/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string59 = "jaredhaight/PSAttackBuildTool" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string60 = "KexMnyvBHcpAfniIdwPEXIgPdlxiUNMrYkSMrnXcdVOYYeoscIbuQssBxijBANhu" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string61 = /PowerView\.ps1/ nocase ascii wide
        // Description: PS>Attack combines some of the best projects in the infosec powershell community into a self contained custom PowerShell console. Its designed to make it easy to use PowerShell offensively and to evade antivirus and Incident Response teams. It does this with in a couple of ways.
        // Reference: https://github.com/jaredhaight/PSAttack
        $string62 = "PSAttack" nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string63 = /PSAttack\.exe/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string64 = /PSAttack\.Resources\.BuildDate\.txt/ nocase ascii wide
        // Description: PSAttack contains over 100 commands for Privilege Escalation - Recon and Data Exfilitration
        // Reference: https://github.com/GDSSecurity/PSAttack
        $string65 = /VolumeShadowCopyTools\.ps1/ nocase ascii wide

    condition:
        any of them
}
