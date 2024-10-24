rule FruityC2
{
    meta:
        description = "Detection patterns for the tool 'FruityC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FruityC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string1 = /\s\-DumpCreds\s\-ComputerName\s/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string2 = /\s\-ServiceName\sVulnSVC\s/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string3 = /\/fruityc2\.crt/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string4 = /\/FruityC2\.git/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string5 = /\/fruityc2\.key/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string6 = /\/fruityc2\.pem/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string7 = /\/FruityC2\/archive\/master\.zip/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string8 = /\/FruityC2\/releases\// nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string9 = /\/FruityC2\-Client/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string10 = /\\FruityC2\-Client/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string11 = /\\ps_encoder\.py/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string12 = /\\ps_proxy\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string13 = /\\ps_stager\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string14 = /\\PSReflect\.psm1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string15 = /\<H1\>PowerUp\sreport\sfor\s/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string16 = /\<H2\>Vulnerabl\sSchasks/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string17 = /028648d9410d8aaf65b7cb4999999947b55f8aa4db3ec24ff82b601b77ecc335/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string18 = /069a9a0aece20ae241fe75e4ba6e1338f8292bf9510182883f649a32fe27604c/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string19 = /21fff74c2464be8072328345721555138aed7e15adc531ae4f244820a0f3061f/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string20 = /2e0680b916b117d6eff7e621212b7ac6f28c41b95a3fc18b91b13922e3e2e72f/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string21 = /39f719f490cdea6b7566c0ad99a6c70b6d241f80328a82a403f33468a91744f2/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string22 = /3a87abf646b679217d7c67e45c5df4bac7b3ea9f5e33ccd7ad82b964d0bc73a7/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string23 = /40b10d676e40a4c5c006f2d8b92cd5fa069b83348612d052e626e7792b4edbf7/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string24 = /4260354c3960e04e73b36289099665ce1cb839d1c56696639e782643c98dbe7b/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string25 = /488785c691425b7cb3c355b1ae38a0527faf339f68a3536f34e1ee10c627790c/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string26 = /4f5f8bd4df664f10dbd919129bbf7d8c6c8a02da74b36a20c322b5a1ce257249/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string27 = /5241f01eb654fe100e0c2a973b7f2443e7bcd914e5b388cc07031871a7d4d199/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string28 = /55b47d76298d6f56ea19a06c6bab41145675717159890d4787fe83c8785bbf23/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string29 = /5f346d82d780b573ffd6e4ae1051dd96d10d5141d17535d5538ae8713096085b/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string30 = /6cc72a74c01d04cf06cca303ba6a584a4261829d88fde64592e5a04cb0a16522/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string31 = /7af03cf989ce48137cd2b74c1020fc42241d7dea7ffaf6ff67f16a23a302ad80/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string32 = /99f14934d82a3db78f0f68017c079ec04dedddc5890bf5ce5194dd30801f779d/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string33 = /a71ca78d1c4b0dc8d6c35c883b18034a5b505886cc74fed0003c5e095494b1c8/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string34 = /adaptivethreat\/Empire/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string35 = /b4af4df46eb9a169f197c093325d983db5dc0ab1eb6bd7aa67458e4f48c2e0b2/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string36 = /Create\sSSL\scertificate\s\(FruityC2\)/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string37 = /dec9c3346c770a93bd7f1fb1b891100d806ecc70f1c5da84ea001aa0efb3694d/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string38 = /Downloading\sAD\-Recon\sPS\sscripts/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string39 = /Downloading\sEmpire\sPS\sscripts/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string40 = /Downloading\sFruityC2/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string41 = /Downloading\sNishang\sPS\sscripts/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string42 = /Downloading\sPowerSploit\sPS\sscripts/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string43 = /e1966d7c2abe5f6f610c745858ab19a48b1b4ee7db738e15f4bb8b1009f38eb9/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string44 = /e35cdc81954fb9701b5fd2f79300a5a6b2dd018e82aa733727a734b08ddd9715/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string45 = /eeba4c8ec806378fecc51fb7ffe3b48c5fa57108330b822043494cc4cea99d89/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string46 = /FruityC2\.py/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string47 = /Get\-ExploitableSystem\.psm1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string48 = /Get\-ExploitableSystems\.psm1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string49 = /Get\-PassHashes\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string50 = /Get\-Screenshot\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string51 = /Get\-SPN\-FruityC2\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string52 = /http\:\/\/127\.0\.0\.1\:50000\/payload\/upload/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string53 = /Invoke\-ACLScanner/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string54 = /Invoke\-CheckLocalAdminAccess\s\-ComputerName\s/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string55 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string56 = /Invoke\-FileFinder\s\-ShareList\s/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string57 = /Invoke\-FruityC2/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string58 = /Invoke\-ImpersonateUser/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string59 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string60 = /Invoke\-PatchDll\s\-DllBytes\s/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string61 = /invoke\-reflectivedllinjection\-ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string62 = /Invoke\-ServiceAbuse/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string63 = /Invoke\-StealthUserHunter\s/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string64 = /Invoke\-TokenManipulation\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string65 = /PostExploitation\.psm1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string66 = /powershell\-import\s\/var\/www\/ps\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string67 = /PowerUp\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string68 = /PowerView\.ps1/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string69 = /PyroTek3\/PowerShell\-AD\-Recon/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string70 = /samratashok\/nishang/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string71 = /standard\:\:base64.{0,1000}kerberos\:\:list\s\/export/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string72 = /Write\-HijackDll\s\-OutputFile/ nocase ascii wide
        // Description: ruityC2 is a post-exploitation framework based on the deployment of agents on compromised machines
        // Reference: https://github.com/xtr4nge/FruityC2
        $string73 = /xtr4nge\/FruityC2/ nocase ascii wide

    condition:
        any of them
}
