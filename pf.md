## 1. Introduction

Servers communicate over the network by sending and receiving "packets" of data. Each packet is directed to a combination of an IP address and a port number.

In order for the operating system to receive data on a port, the port has to be *open*. The network stack (TCP/IP) receives packets on open ports and places them in the memory (RAM) in specific structures called packet buffers. From here, the packets undergo further processing by higher level stacks, such as application layer programs.

When a server is connected to an *untrusted* network (such as the Internet), malicious actors can try to access the server. Attackers can try to send malware and viruses to the server to take control of it.

The solution is to restrict and control access to the server. Other computers on the network should be allowed to access only specific ports (services) on the server. A web server might have only its *http* and *https* ports open and close off most or all other ports. Packets addressed to closed ports are rejected. Similarly, it is possible to reject packets from specific IP addresses, or to only accept packets from specified IP addresses. It is also possible to have more complex rules by combining simpler rules. For example, you might want to accept packets only from certain IP addresses and only on certain port numbers; for example, you might want to do this on a private FTP server, or to protect SSH access. You control the computer's network access with a firewall.

On BSD systems, a commonly used firewall is `pf`, short for *packet filter*.

### The `pf` Firewall

`pf` firewall rules look like:

    pass in on $ext_if proto tcp to port $myssh keep state (max-src-conn 9, max-src-conn-rate 9/100, overload <blocked_guests> flush global)

The line above is from a production webserver.

To be able to read and understand the rules in firewalls you come across in the wild, and to be able to compose rules yourself (instead of only copying lines off the internet), it is vital to understand the basics - the structure and syntax of a `pf` config file.

**NOTICE:** Do not blindly copy any example config statements without knowing exactly what it is for, and why your setup needs it. A messed up firewall configuration can render your server inaccessible to visitors and even to yourself (this scenario is covered in Section 4.1.1 and 4.1.2).

### How it works

The `pf` config file is written as a series of statements (explained further in the next section). Each statement is either a declaration or a rule. Packet filtering refers to blocking or allowing a certain packet. This is done by following the set of rules specified in the config file. Rules can be written to either affect all packets, or only packets meeting certain conditions (e.g. incoming on a certain port number). For each packet, the rules are evaluated sequentially from top to bottom. By default, each packet is allowed to pass through (which it does, in the absence of the firewall).

Each rule (which matches the incoming packet) can change whether the packet is allowed to pass through or if it is blocked. **The last matching rule actually decides whether the packet is allowed or blocked.**

### Article Outline

After the introductory Section 1, this article gives a summary overview of the structure and syntax of `pf` in Sections 2 and 3 to first make you comfortable with the underlying principles of a `pf` config file. Section 4 has a number of hands-on examples to help you get started writing your own firewall.

### Prerequisites

To follow this guide, you need:

* Some experience working in the shell,  basic terminal operations, and editing files with a terminal based text editor like `vi` or `vim`.

* Ideally (highly advisable, but not strictly necessary), some experience writing and executing simple shell scripts.

* Ideally, some experience using a window manager like [Screen](https://www.vultr.com/zh/docs/an-introductory-guide-to-screen) or [Tmux](https://www.vultr.com/docs/how-to-install-and-use-tmux/).

* Access to a server running a BSD-based operating system (FreeBSD or OpenBSD) with at least 1 GB of RAM. This server can be running either remotely, or on a virtual machine on your local system.

* ssh access from your local machine to the server.

* root access on the server. Most, if not all, operations involving the firewall need root access.

To do this on a remote server, follow these steps to get started:

* [Deploy a cloud server at Vultr](https://my.vultr.com/deploy/)

* [Update the server](https://www.vultr.com/docs/update-debian-server-best-practices).

* [Create a non-root user with sudo privileges](https://www.vultr.com/docs/create-a-sudo-user-on-debian-best-practices).

* [Log in to your server](https://www.vultr.com/docs/how-to-access-your-vultr-vps) as a non-root user.

* It is strongly recommended [to use SSH login with remote servers](https://www.vultr.com/docs/how-to-use-ssh-with-vultr-servers/) and to [disable password-based login](https://www.vultr.com/docs/how-to-secure-ssh-on-arch-linux/).

### Compatibility

This guide has been thoroughly tested on **FreeBSD 13.0-RELEASE**. In general, it should be compatible with all recent FreeBSD and OpenBSD operating systems.

## 2. Statements

There are **seven** different types of statements. You are supposed to group together statements of a given type. You are also supposed to have the groups of statements in the order below. This means the first group of statements in your `pf` config should be *macros*, followed by *tables*, followed by *options*, and so on.

### 2.1 Macros

Macros are like variables in a regular programming language. Macros are simple to use:

    db_port=5432

This will allow you to use `$db_port` instead of the port number 5432 throughout the config file. Macros need to be defined before they can be used, just like variables.

### 2.2 Tables

Tables group and hold a number of IP addresses under a common name. This makes it possible to have rules like blocking incoming packets from all addresses in a table.

    table <sshguard> persist

This statement creates a table with the name *sshguard*. The *persist* keyword instructs the OS to retain the table even when there are no rules referring to it. The default behavior is to remove tables that are not used in a rule.

    block quick from <sshguard>

This is a rule to block all incoming connections from clients (IP addresses) listed in the table *sshguard*. The *quick* keyword is discussed in a later subsection.

### 2.3. Options

Option statements are for setting pf-wide settings.

    set block-policy drop 

This option sets a default policy that blocked packets are dropped.

Options are also used to tune the performance of the firewall. You can set options for things like:

#### 2.3.1. Limits on resources that `pf` can use

    set limit frags 10000

This option sets the maximum number of entries (fragments) stored in memory for packet reassembly.

    set limit table-entries 500000

This option sets the maximum number of tables or entries per table.

#### 2.3.2. Choice of pre-defined optimization profile

    set optimization high-latency

This option is for high latency networks like satellite internet.

**WARNING:** Unless otherwise mentioned, do not copy any of the example config statements without knowing exactly why your setup needs it. The default settings of `pf` are sufficient for most standard use-cases.

### 2.4 Traffic Normalization

Traffic normalization statements are about "normalizing" packets - this process is called *scrubbing*. For instance, you might want to disallow packets which have a TTL less than a certain minimum value.

    scrub in all

This option instructs the firewall to scrub all incoming packets.

### 2.5 Queuing

Queuing allows to control the bandwidth based on certain rules. By default, the GENERIC FreeBSD kernel does not include the necessary modules to do this. You will need to compile a custom kernel to use queuing. This is a relatively advanced topic which will not be covered in this guide.

### 2.6 Translation Rules

Translation rules are for modifying the source or destination address of a packet. This is useful for doing things like redirecting packets to different ports (for example, a custom ssh port) or network interfaces.

    rdr in on $ext_if -> $int_if

This rule redirects *incoming* packets on the `$ext_if` network interface to the `$int_if` network interface.

Another use case is for doing Network Address Translation (NAT) - translating "internal" network addresses (e.g. 2.168.x.y) to the external IP address of the server.

    nat on $ext_if from $int_if to any -> ($ext_if)

This rule acts on the `$ext_if` (external) network interface: all packets coming from the `$int_if` (internal) network interface (and going out to any address) get their address translated to that of the `ext_if` interface.

### 2.7 Packet Filtering Rules

Filtering refers to one of two actions - *pass* or *block*. Filtering rules start with either of these action words.

    pass in on $int_if

This rule allows incoming packets on the `$int_if` interface.

    block from <blocked_guests>

This rule blocks incoming packets from all addresses in the table *blocked_guests*.

## 3. Parameters

Parameters specify which packets a rule applies to.

Some commonly used parameters are:

### 3.1. `in` and `out`

This specifies whether the rule should apply to incoming or outgoing packets. The default (if nothing is specified) is to apply the rule to both incoming and outgoing packets.

    block in

This, in itself, means incoming packets are to be blocked.

### 3.2. `on`

This specifies that the rule should apply only to packets through certain network interfaces.

    pass in on $int_if

This means incoming packets on the network interface (denoted by the macro) `$int_if` should be allowed to pass.

### 3.3. `from` and `to`

This specifies that the rule should apply only to packets coming from certain sources and directed to certain destinations.

   block from <blocked_guests>

This rule asks the firewall to block incoming packets from any IP addresses in the table `blocked_guests`.

### 3.4. `log`

This parameter specifies that packets matching that rule should be logged. Logs are written to `pflog`.

   block in log (all) from <blocked_guests>

### 3.5 `quick`

The `quick` keyword added to a matching rule causes `pf` to not process any further rules for that packet. In other words, if a rule with the keyword `quick` matches a certain packet, that rule is the last one applied, and no further rules are processed for that packet.

   block quick from <blocked_guests>

### 3.6. `proto`

This specifies that the rule applies only when the packet of certain protocols.

    pass in proto tcp

This rule means that incoming TCP packets should be allowed to pass through.

### 3.7. `all`

The all parameter means that the rule applies to packets from any source to any destination.

    block in all

This rule means all incoming packets are to be blocked.

There are many other parameters, which will not be discussed here.

## 4. Practical Examples

This section looks at some simple and commonly encountered use-cases. This section assumes that you are logged in to the server via SSH.

### 4.1. Getting Started

FreeBSD and OpenBSD both come with `pf` preinstalled. `pf` stands for Packet Filter. `pfctl` is the tool for managing `pf`. On OpenBSD, `pf` is enabled by default. On FreeBSD, however, it is not enabled by default. You will need to enable it.

The default settings for FreeBSD are:

* When you start `pf`, the configuration in the file `/etc/pf.conf` is loaded.

* Only the `root` user can modify this file.

* There is no `/etc/pf.conf` file; you will need to create it before starting `pf`.

To check if `pf` is already enabled in the system you are on, check the `sysrc` setting:

    # sysrc pf_enable

If `pf` is not enabled, the output should either be empty or "NO":

    pf_enable: 
    pf_enable: NO

The first step in enabling `pf` is to add an entry in the `rc.conf` file. It is possible (but not recommended) to directly edit the `/etc/rc.conf` file with a text editor like `vi`. The preferred approach is to use the `sysrc` command:

    # sysrc pf_enable="YES"

It is also recommended to enable logging on `pf`.

    # sysrc pflog_enable="YES"

Create an empty config file before starting `pf`:

    # touch /etc/pf.conf

After enabling `pf` in the `rc` file, reboot the system or start the `pf` service manually:

    # service pf start

You can disable the packet filter using:

    # pfctl -d

To re-start pf after disabling it:

    # pfctl -e

To start pf and load the configuration in a specific file, use the option `-f`:

    # pfctl -e -f /path/to/config_file

#### 4.1.1. Be Careful

Errors in the packet filter settings can lead to you getting inadvertently locked out of your own server. This is a very bad position to be in. You will need physical access to the server so you can log in at the terminal and change back the `pf` setting to allow ssh access again. Some server vendors like Vultr have a virtual [Web Console](https://www.vultr.com/docs/vultr-web-console-faq/), which, in effect, is the same as getting physical access to the server. You can log in to the web console, `su` to root, and fix the config file to re-allow ssh access. If none of these options are available, the only way out is to reinstall the OS and start afresh.

#### 4.1.2. Preparation

To avoid facing the difficult situation of getting locked out of your own server, it is prudent and advisable to use a shell script with a timer which will roll back any changes you made to the configuration. So the new configuration will get rolled back when the timer expires. If you broke something, you can log back in when the old (working) configuration is reloaded after the timer expires. If everything worked out as expected, you can then make the changes permanent. Open a new file titled `pftimer.sh` in your home directory `/home/your_user_name`:

    $ vi /home/your_user_name/pftimer.sh

Modify the script below to suit your needs and add it to the file.

    #!/bin/sh

    # first disable pf just in case you started it earlier and left it running
    pfctl -d

    # start `pf` (or enable `pf` with the new configuration file)
    pfctl -e -f /etc/pf.conf

    # sleep for some time - as much as you need to test out the new settings
    sleep 30

    # disable `pf` 
    pfctl -d

    # pfctl -e -f /etc/pf.conf.OLD # uncomment this line to re-enable the old working configuration

Save the script. Change the ownership and permissions of this script so that your unprivileged user account can write to it, and only the root can execute it.

    # chown root:wheel pftimer.sh

    # chmod 760 pftimer.sh

It is equally prudent to first make a backup copy of the working configuration file before making changes to it. This will allow you to easily roll back to an earlier configuration in case you made a mistake.

#### 4.1.3. Dry-runs

When you try to write your own rules, you will make mistakes - both syntactic and logical. Use the script approach described above to mitigate the effects of logical errors. To detect syntactic errors, do a dry-run. This test the configuration without loading the rules.

    # pfctl -nf /path/to_config_file

#### 4.1.4. The current configuration

To view the current configuration of `pf`, invoke `pfctl` with the `-s` option and the modifier `rules`:

    # pfctl -s rules

This will "show" the current filter rules.

Similarly, to view the current NAT redirection rules, use the modifier 'nat':

    # pfctl -s nat

To view summary information about the overall activity of the firewall:

    # pfctl -s info

To view the list of network interfaces that can be used with `pf`:

    #pfctl -s Interfaces

`pfctl -s all` will show a complete overview (excluding the list of tables) of the current setup.

### 4.2. Blocking Traffic

If you have been following the article so far, at this point `pf` is enabled with an empty config file.

#### 4.2.1 Blocking All Traffic

Open the config file:

    # vi /etc/pf.conf

Add to it a single line and save the file.

    block all

This blocks all - incoming and outgoing traffic.

Get the IP address of the server using `ifconfig`. Make sure that you are able to ping the server. You will need to test this in a moment.

Enable pf temporarily by running the script you wrote earlier:

    # /home/your_user_name/pftimer.sh

This should fire up the firewall with the `block all` statement. The ssh session you are in should suddenly stop responding. In another terminal window, try to ping the IP address of the server. The ping will not respond and time out. After 30 seconds (or whatever sleep timer you have in your script), ping should resume. Your ssh session might already have broken and disconnected. Connect to the server again with a new ssh session. Everything should be back to normal.

**NOTE:** It is a good idea to first start a Tmux or Screen session and do the above tests in a window manager. If you temporarily lose ssh connectivity due to a (deliberate or accidental) misconfiguration, the old working configuration will be back after the timer. You can then reconnect to your old window manager session and avoid having to reopen all previously open files.

In a real life scenario, you will have many other statements in the config file. Some of them can override the `block` rule. To ensure that the rule is the one applied on all packets, use the keyword quick. Place the blocking rule as the first rule. In order that this rule is enforced, there should be no other rules with the keyword `quick` before this rule. So the structure of the config file should resemble something like:

    # macro declaration statements

    # table declaration statements

    block quick all

    # all other rules

Note that the comment prefix `#` in the sample code block above is to indicate the relative location of groups of statements. The statements themselves do not need to be commented out.

To temporarily block all traffic on a production server, another approach to consider is making a new configuration file with just the `block all` rule statement. Use the script in Section 4.1.2 to temporarily enable this new file. Uncomment the last line so that at the end of the timeout, the old working configuration file (the one that doesn't block all traffic) is re-enabled.

#### 4.2.2 Blocking Selected Traffic

Use different parameters (Section 3) to selectively apply the blocking rule.

    block in all
    block in quick all

These rule statements block all incoming traffic. But outgoing traffic is not affected.

    block out all
    block out quick all

These rule statements block all outgoing traffic. But incoming traffic is not affected.

### 4.3. Allowing Traffic

In the previous subsection, packet filtering rules with the action word `block` are used to block traffic. Similarly, the action word `pass` is used to write rules to allow traffic to pass through.

#### 4.2.1 Allowing All Traffic

    pass all

This rule allows all traffic - incoming and outgoing to pass through. Everything in the previous section is directly applicable here - just replace `block` with `pass`.

#### 4.2.2. Demonstrating `quick` 

Open the config file and modify it so it looks as below:

    pass quick all

    block all # or any other variants of the block rules

Enable the firewall temporarily by running the script you wrote earlier:

    # /home/your_user_name/pftimer.sh

Your current connection *might* get uninterrupted but ping should be normal and you should be able to open a new ssh connection to the server. 

Here the first rule encountered allows all traffic to pass through. The `quick` keyword ensures that no other rules are checked for packets that match the first rule. Since the first rule applies to all packets, no other rules are checked for any packet. Hence all traffic passes through. The block rules are effectively ignored.


#### 4.1. HTTP(S) traffic

## Conclusion

Packet filtering is a vast and extensive topic. Subsequent to this introductory guide, an interesting topic to learn about is using tables to restrict access to certain hosts, and using `pf` in conjunction with other tools like `sshguard`. The best reference for `pf` is [the official documentation from the OpenBSD project](https://www.openbsd.org/faq/pf/filter.html). The [FreeBSD manual page](https://www.freebsd.org/cgi/man.cgi?query=pf.conf) is a very good operational guide. [The Book of PF](https://books.google.co.in/books?id=7gcvDwAAQBAJ) is the authoritative source for everything about it.


LINKS

https://vultrdocs.notion.site/pf-Quickstart-Guide-155b4a0fa39c4d8b93fac0304cb80d25

https://www.digitalocean.com/community/tutorials/how-to-configure-packet-filter-pf-on-freebsd-12-1

https://www.openbsd.org/faq/pf/options.html

https://www.openbsd.org/faq/pf/filter.html

https://www.freebsd.org/cgi/man.cgi?query=pf.conf

https://www.openbsd.org/faq/pf/logging.html

https://man.openbsd.org/pf

https://man.openbsd.org/pf.conf

https://people.freebsd.org/~rodrigc/doc/handbook/firewalls-pf.html




https://community.letsencrypt.org/t/renewing-of-certificate-manually-behing-firewall/168337

https://www.vultr.com/docs/setup-letsencrypt-on-linux/

https://community.letsencrypt.org/t/lets-encrypt-server-addresses-for-certificate-renewal/83466/4

https://letsencrypt.org/docs/integration-guide/#firewall-configuration

https://community.letsencrypt.org/t/renewal-do-i-need-ports-80-and-or-443-to-open/145319

