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
        $string3 = /\s\-c\s\-w\s.*\.txt\s\-w\s.*\.txt\s\-\-ss\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string4 = /\s\-c\s\-w\smethods\.txt\s\-p\s127\.0\.0\.1/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string5 = /\s\-c\s\-w\susers\.txt\s\-\-hs\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string6 = /\s\-c\s\-z\sfile.*users\.txt\s\-z\sfile.*pass\.txt\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string7 = /\s\-c\s\-z\srange.*1\-10\s\-\-hc\=BBB\shttp/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string8 = /\scommon_pass\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string9 = /\sFUZZ:FUZZ\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string10 = /\sinstall\swfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string11 = /\s\-\-script\=robots\s\-z\slist.*robots\.txt.*http/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string12 = /\s\-u\sFUZZ\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string13 = /\s\-w\swordlist\/.*\.txt.*http/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string14 = /\sws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string15 = /\sws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string16 = /\s\-X\sFUZZ\shttp/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string17 = /\s\-z\sburplog/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string18 = /\s\-z\sfile.*wordlist\// nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string19 = /\s\-z\slist.*nonvalid\-httpwatch\s\-\-basic/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string20 = /\s\-z\srange\s\-\-zD\s0\-1\s\-u\shttp/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string21 = /\s\-z\srange.*0\-10\s\-\-hl\s97\shttp/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string22 = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string23 = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/shadow/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string24 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/boot\.ini/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string25 = /\/admin\-panels\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string26 = /\/All_attack\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string27 = /\/common_pass\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string28 = /\/Injections\/SQL\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string29 = /\/sql_inj\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string30 = /\/ws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string31 = /\/ws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string32 = /\\admin\-panels\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string33 = /\\All_attack\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string34 = /\\common_pass\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string35 = /\\ws\-dirs\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string36 = /\\ws\-files\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string37 = /buffer_overflow\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string38 = /burp_log_.*\.log/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string39 = /burpitem\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string40 = /burplog\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string41 = /burpstate\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string42 = /dirTraversal\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string43 = /dirTraversal\-nix\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string44 = /dirTraversal\-win\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string45 = /dirwalk\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string46 = /from\s\.core\simport\sFuzzer/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string47 = /from\s\.wfuzz\simport\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string48 = /fuzzfactory\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string49 = /fuzzrequest\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string50 = /http:\/\/127\.0\.0\.1\/FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string51 = /http:\/\/wfuzz\.org/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string52 = /https:\/\/wfuzz\.readthedocs\.io/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string53 = /import\swfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string54 = /Injections\/Traversal\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string55 = /Injections\/XSS\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string56 = /shodanp\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string57 = /site\-packages\/wfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string58 = /subdomains\-top1million\-20000\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string59 = /uname\=FUZZ\&pass\=FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string60 = /vulns\/apache\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string61 = /vulns\/iis\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string62 = /vulns\/jrun\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string63 = /vulns\/tomcat\.txt/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string64 = /vulnweb\.com\/FUZZ/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string65 = /wfencode\s\-/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string66 = /wfencode\s\-e\s/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string67 = /wfencode\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string68 = /wfencode\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string69 = /wfpayload\s\-/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string70 = /wfpayload\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string71 = /wfpayload\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string72 = /wfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string73 = /wfuzz\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string74 = /wfuzz\.get_payload/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string75 = /wfuzz\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string76 = /wfuzz\.wfuzz/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string77 = /wfuzz\-cli\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string78 = /wfuzzp\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string79 = /www\.wfuzz\.org/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string80 = /wxfuzz\.bat/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string81 = /wxfuzz\.py/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string82 = /xmendez\/wfuzz/ nocase ascii wide

    condition:
        any of them
}