rule quiet_riot
{
    meta:
        description = "Detection patterns for the tool 'quiet-riot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "quiet-riot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string1 = /\secrprivenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string2 = /\secrpubenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string3 = /\siamassumeroleenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string4 = /\slambdaenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string5 = /\sloadbalancer\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string6 = /\ss3aclenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string7 = /\ss3enum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string8 = /\ssecretsmanagerenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string9 = /\ssnsenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string10 = /\/ecrprivenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string11 = /\/ecrpubenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string12 = /\/iamassumeroleenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string13 = /\/lambdaenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string14 = /\/loadbalancer\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string15 = /\/quiet\-riot\.git/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string16 = /\/s3aclenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string17 = /\/s3enum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string18 = /\/secretsmanagerenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string19 = /\/snsenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string20 = /\/wordlists\/combined_male_names\.txt/
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string21 = /\/wordlists\/familynames\-usa\-top1000\.txt/
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string22 = /\/wordlists\/femalenames\-usa\-top1000\.txt/
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string23 = /\/wordlists\/malenames\-usa\-top1000\.txt/
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string24 = /\/wordlists\/names_quit_riot\.txt/
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string25 = /\\ecrprivenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string26 = /\\ecrpubenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string27 = /\\iamassumeroleenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string28 = /\\lambdaenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string29 = /\\loadbalancer\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string30 = /\\quiet\-riot\-main/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string31 = /\\s3aclenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string32 = /\\s3enum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string33 = /\\secretsmanagerenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string34 = /\\snsenum\.py/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string35 = "1f4fc2020e9da18d8783fe9e98b702229756849eb1ef87ee199a94c8ab123f10" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string36 = "6aa39b4578eae70ad9e80df833b4633a5e78eda7b75b071d14f0a3befdf81223" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string37 = "75d5f38d2dd472c4d54999cf9b023c92ccb2f5806e78d610325707cb2b8aaa2f" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string38 = "7cc0f7c80a3b90b1fed9a972ec241328cbc47edd1eede88bcf24933cc55c0e12" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string39 = "b22850c4a39e5abf07c8e91b943cd477f31a21dc6942801e58d756782cfbc095" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string40 = "ca6a84b59ef6e40ee3657dd79a54706818d66345725434ade357898aa6722f62" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string41 = "d75e6210055b8ace4fb94f7108604081c957b97ce17772efd58d7ff845589ce0" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string42 = "e5f826920a0effa33441079ae4eb87f7dc31534bb6577ba322f13c7d838d5b17" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string43 = "f2f1896de3273d47b9d6831b9ac66c1a8fbbde28eb433bef65495ffcb81c9105" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string44 = /from\s\.enumeration\simport\secrprivenum/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string45 = /from\s\.enumeration\simport\secrpubenum/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string46 = /from\s\.enumeration\simport\sloadbalancer\sas\sloadbalancer/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string47 = /from\s\.enumeration\simport\srand_id_generator\sas\srand_id_generator/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string48 = /from\s\.enumeration\simport\ss3aclenum\sas\ss3aclenum/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string49 = /from\s\.enumeration\simport\ssnsenum/ nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string50 = "pip install quiet-riot" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string51 = "Quiet Riot discovered one valid e-mail account" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string52 = "Quiet Riot discovered one valid login account" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string53 = "quiet_riot --scan_type" nocase ascii wide
        // Description: Unauthenticated enumeration of AWS - Azure and GCP Principals
        // Reference: https://github.com/righteousgambit/quiet-riot
        $string54 = "righteousgambit/quiet-riot" nocase ascii wide
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
