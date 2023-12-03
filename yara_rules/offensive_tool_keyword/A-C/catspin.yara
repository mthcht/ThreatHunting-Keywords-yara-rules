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
        $string1 = /.{0,1000}\scatspin\.sh\s.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string2 = /.{0,1000}\sfile:\/\/catspin\.yaml\s.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string3 = /.{0,1000}\s\-\-stack\-name\scatspin\s.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string4 = /.{0,1000}\/catspin\.git.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string5 = /.{0,1000}\/catspin\-main\/.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string6 = /.{0,1000}\/execute\-api\.eu\-central\-1\.amazonaws\.com\/catspin_deployed.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string7 = /.{0,1000}\[\+\]\sUse\s\-info\sto\sget\sstack\sstatus\sand\sthe\senpoint\surl\sof\scatspin.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string8 = /.{0,1000}\[\+\]\sYou\sspin\smy\sgato\sround\sright\sround\s\?.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string9 = /.{0,1000}\\catspin\-main\\.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string10 = /.{0,1000}catspin\.sh\shttp.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string11 = /.{0,1000}catspin\.sh\s\-info.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string12 = /.{0,1000}catspin\.sh\s\-kill.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string13 = /.{0,1000}catspin\.sh\s\-run\s.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string14 = /.{0,1000}catspin_for_readme\.mp4.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string15 = /.{0,1000}catspin_poc\.mp4.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string16 = /.{0,1000}catspin_poc_final\.mp4.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string17 = /.{0,1000}rootcathacking\/catspin.{0,1000}/ nocase ascii wide
        // Description: Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.
        // Reference: https://github.com/rootcathacking/catspin
        $string18 = /.{0,1000}Spins\sup\scatspin\susing\sApi\sGateway\sproxy.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
