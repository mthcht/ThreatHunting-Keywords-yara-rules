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
        $string6 = /\sFUZZ\:FUZZ\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string7 = /\sinstall\swfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string8 = /\s\-u\sFUZZ\s/ nocase ascii wide
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
        $string12 = /\s\-X\sFUZZ\shttp/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string13 = /\s\-z\sburplog/ nocase ascii wide
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
        $string21 = /\/ws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string22 = /\/ws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string23 = /\\admin\-panels\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string24 = /\\All_attack\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string25 = /\\common_pass\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string26 = /\\ws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string27 = /\\ws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string28 = /buffer_overflow\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string29 = /burp_log_.{0,1000}\.log/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string30 = /burpitem\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string31 = /burplog\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string32 = /burpstate\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string33 = /dirTraversal\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string34 = /dirTraversal\-nix\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string35 = /dirTraversal\-win\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string36 = /dirwalk\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string37 = /from\s\.core\simport\sFuzzer/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string38 = /from\s\.wfuzz\simport\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string39 = /fuzzfactory\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string40 = /fuzzrequest\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string41 = /http\:\/\/127\.0\.0\.1\/FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string42 = /http\:\/\/wfuzz\.org/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string43 = /https\:\/\/wfuzz\.readthedocs\.io/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string44 = /import\swfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string45 = /Injections\/Traversal\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string46 = /Injections\/XSS\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string47 = /shodanp\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string48 = /site\-packages\/wfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string49 = /subdomains\-top1million\-20000\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string50 = /uname\=FUZZ\&pass\=FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string51 = /vulns\/apache\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string52 = /vulns\/iis\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string53 = /vulns\/jrun\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string54 = /vulns\/tomcat\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string55 = /vulnweb\.com\/FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string56 = /wfencode\s\-/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string57 = /wfencode\s\-e\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string58 = /wfencode\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string59 = /wfencode\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string60 = /wfpayload\s\-/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string61 = /wfpayload\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string62 = /wfpayload\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string63 = /wfuzz/ nocase ascii wide
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
        $string73 = /xmendez\/wfuzz/ nocase ascii wide

    condition:
        any of them
}
