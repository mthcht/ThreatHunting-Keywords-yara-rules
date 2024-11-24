rule wfuzz
{
    meta:
        description = "Detection patterns for the tool 'wfuzz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wfuzz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string1 = /\sadmin\-panels\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string2 = /\sAll_attack\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string3 = /\s\-c\s\-w\smethods\.txt\s\-p\s127\.0\.0\.1/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string4 = /\s\-c\s\-z\srange.{0,1000}1\-10\s\-\-hc\=BBB\shttp/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string5 = /\scommon_pass\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string6 = " FUZZ:FUZZ " nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string7 = " install wfuzz" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string8 = " -u FUZZ " nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string9 = /\s\-w\swordlist\/.{0,1000}\.txt.{0,1000}http/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string10 = /\sws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string11 = /\sws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string12 = " -X FUZZ http" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string13 = " -z burplog" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string14 = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string15 = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/shadow/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string16 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/boot\.ini/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string17 = /\/admin\-panels\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string18 = /\/All_attack\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string19 = /\/Injections\/SQL\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string20 = /\/sql_inj\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string21 = "/wfuzz " nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string22 = /\/ws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string23 = /\/ws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string24 = /\\admin\-panels\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string25 = /\\All_attack\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string26 = /\\common_pass\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string27 = /\\ws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string28 = /\\ws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string29 = /buffer_overflow\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string30 = /burp_log_.{0,1000}\.log/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string31 = /burpitem\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string32 = /burplog\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string33 = /burpstate\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string34 = /dirTraversal\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string35 = /dirTraversal\-nix\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string36 = /dirTraversal\-win\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string37 = /dirwalk\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string38 = /from\s\.core\simport\sFuzzer/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string39 = /from\s\.wfuzz\simport\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string40 = /fuzzfactory\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string41 = /fuzzrequest\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string42 = /http\:\/\/127\.0\.0\.1\/FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string43 = /http\:\/\/wfuzz\.org/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string44 = /https\:\/\/wfuzz\.readthedocs\.io/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string45 = "import wfuzz" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string46 = /Injections\/Traversal\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string47 = /Injections\/XSS\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string48 = /shodanp\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string49 = "site-packages/wfuzz" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string50 = /subdomains\-top1million\-20000\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string51 = "uname=FUZZ&pass=FUZZ" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string52 = /vulns\/apache\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string53 = /vulns\/iis\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string54 = /vulns\/jrun\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string55 = /vulns\/tomcat\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string56 = /vulnweb\.com\/FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string57 = "wfencode -" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string58 = "wfencode -e " nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string59 = /wfencode\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string60 = /wfencode\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string61 = "wfpayload -" nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string62 = /wfpayload\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string63 = /wfpayload\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string64 = /wfuzz\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string65 = /wfuzz\.get_payload/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string66 = /wfuzz\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string67 = /wfuzz\.wfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string68 = /wfuzz\-cli\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string69 = /wfuzzp\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string70 = /www\.wfuzz\.org/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string71 = /wxfuzz\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string72 = /wxfuzz\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string73 = "xmendez/wfuzz" nocase ascii wide

    condition:
        any of them
}
