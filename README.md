honeycred
----------------------------------

honeycred is a utility utilized to seamlessly inject and preserve honey tokens into lsass. 

Usage
----------------------------------

By default, honeycred will inject credentials into memory with the username **contoso.com\svc_dlp**, the password **foobar9000**, and run a process called **agent.exe**. 

It's recommended that you change this. These values can be modified at compile time by changing the default values. Alternatively, they can be specified with command line arguments using **-u** for user, **-pw** for the password, and **-path** for the path. 
