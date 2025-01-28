rule catspin
{
    meta:
        description = "Detection patterns for the tool 'catspin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "catspin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string1 = /\scatspin\.sh\s/
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string2 = /\sfile\:\/\/catspin\.yaml\s/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string3 = " --stack-name catspin " nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string4 = /\/catspin\.git/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string5 = "/catspin-main/" nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string6 = /\/execute\-api\.eu\-central\-1\.amazonaws\.com\/catspin_deployed/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string7 = /\[\+\]\sUse\s\-info\sto\sget\sstack\sstatus\sand\sthe\senpoint\surl\sof\scatspin/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string8 = /\[\+\]\sYou\sspin\smy\sgato\sround\sright\sround\s\?/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string9 = /\\catspin\-main\\/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string10 = /catspin\.sh\shttp/
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string11 = /catspin\.sh\s\-info/
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string12 = /catspin\.sh\s\-kill/
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string13 = /catspin\.sh\s\-run\s/
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string14 = /catspin_for_readme\.mp4/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string15 = /catspin_poc\.mp4/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string16 = /catspin_poc_final\.mp4/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string17 = "rootcathacking/catspin" nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string18 = "Spins up catspin using Api Gateway proxy" nocase ascii wide

    condition:
        any of them
}
