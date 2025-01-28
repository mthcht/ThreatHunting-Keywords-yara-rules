rule spraykatz
{
    meta:
        description = "Detection patterns for the tool 'spraykatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spraykatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string1 = /\sPrintCreds\.py/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string2 = /\sSprayLove\.py/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string3 = /\.dmp\s1\>\s\\\\127\.0\.0\.1\\C\$\\/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string4 = /\/PrintCreds\.py/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string5 = /\/SprayLove\.py/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string6 = /\\PrintCreds\.py/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string7 = /\\SprayLove\.py/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string8 = "2fe32ea10b81598147f6d39cc0ae54a03a5384c73d1fba22fc3f9ae6589ec266" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string9 = "335f1dcefb6d0e3e4a2e97d68d54d87cb53f6ba029a428a048752b19ecca71ad" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string10 = "5e5e21abed5ff9e25cd2ea1c626a1f0ffe6194d1e2c74dfec8aebc0789b2dee1" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string11 = "896106aa70f9ffdb5b219cbc1abcbdcff59bf05a339dcf9a2b9e095160f59e98" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string12 = "be76da790e34b58cd8f35913154aa4d4a749372918cd00324993370bd086ba5a" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string13 = /C\:\\\\SPRAY_.{0,1000}\.dmp/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string14 = /C\:\\SPRAY_.{0,1000}\.dmp/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string15 = /customWmiExec.{0,1000}wmiexec\.py/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string16 = "efe42a7eb08755abbb5c91b36ead35cdafbd82d1e34016046cb4be5861cb2053" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string17 = /listLocalAdminAccess\(/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string18 = /listPwnableTargets\(/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string19 = "nmap -T3 -sT -Pn -n --open -p135 -oG -" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string20 = /No\spwnable\stargets\.\sQuitting\./ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string21 = /pypykatz\.pypykatz/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string22 = "spraykatz" nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string23 = /submodules\.pywerview\.requester/ nocase ascii wide
        // Description: Spraykatz is a tool without any pretention able to retrieve credentials on Windows machines and large Active Directory environments.
        // Reference: https://github.com/aas-n/spraykatz
        $string24 = /tasklist\s\/fi\s.{0,1000}Imagename\seq\slsass\.exe.{0,1000}do\sprocdump/ nocase ascii wide

    condition:
        any of them
}
