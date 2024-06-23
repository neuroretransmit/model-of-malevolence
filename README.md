# model-of-malevolence
Experiments in thinking like a bad guy. Specifics reduced to reduce locking into means/methods except where possible.

**Theoretical protocol vulnerability, scenario, etc. - none of this exists (or maybe it does and you should find it). This was an 
idea I had implementing the QUIC protocol in an out-of-tree kernel module**

## Recon

You put on your black hoodie today and decided to chase the holy grail... a protocol exploit. It should be a commonly used internet standard
in an effort to be the worst bad guy ever. You've been fuzzing and reversing the logic of these protocols for years and always seem to come up
empty... when epiphany strikes. What if we don't attack the protocol itself, but the falibility of human error based on ambiguity
in requirements/definition. In all of your research, you noticed there are a few RFC standards that are ambiguous on the size of
certain parts of their protocol. This is a likely spot for a C-like language to not enforce buffer lengths or never coming back to them
when they weren't defined.

You head over to GitHub and begin looking at various implementations utilizing this protocol in C/C++. You rework your fuzzing tools
to point at a Docker container running these implementations, fire the fuzzers and grab a cup of coffee. When you come back to your box
you realize something very unexpected happened. Not only did the implementations crash - Docker and your machine are gone too. It's
in the middle of a reboot. What happened?

When you are back at a terminal you check kernel/system logs from the last boot and much to your surprise you see the following
without Docker showing a crash at all.

```
[     4.808086] init[1]: segfault at 0 ip    (null) sp bff4645c error 14 in init[8048000+8000]
[     4.808372] Kernel panic - not syncing: Attempted to kill init!
[     4.808442] Pid: 1, comm: init Not tainted 6.2.0-4-x86_64 #1 Debian 3.2.65-1
[     4.808512] Call Trace: 
```

The service you were attacking used a network kernel module for that protocol and it was able to segfault the host. Let's look at
this chain of events and analyze the vulnerabilities/path to exploit.

- Find ambiguity in RFC spec and suspect implementation errors
  - Research common implementations
    - Fuzz protocol
       - to Docker containers
         - to common service with suspected implementation error
           - worse crash than expected
             - discover service executes code in kernel module which reaches into the host
               - host segfaults in kernel module and overwrites instruction pointer during panic
                 - Can we escape a panic but overwrite the instruction pointer to execute our payload?
              

With your heart racing and in an effort to not go to prison, you decide you have to do this right. So long as neighbors are Linux 
boxes - this is a wormable exploit if they can talk on the protocol in question/run the same software.

## Doing it right

### Initial PoC

Your first step into an exploit is figuring out how to take control of execution flow. We already know we have the ability to write out of
a buffer in ring 0 and skipped a lot of the RCE, post-exploitation, privesc, etc. chain to get ring 0.

**PoC payload**

For the PoC - your payload should take control of execution flow by jumping back into the data written to the buffer for devices with an
executable stack. It should also connect a reverse shell back to you.

### Reliable exploit

For the reliable version of this exploit - you need to consider many things. Cross-compilation of payloads for different architectures,
tailoring to different memory protections/processor protections, etc. You want the widest net possible - make sure the reverse shell
is encrypted.

## Devious planning

Now that we have a reliable exploit to blast across the internet, we need to think about how to keep these compromized machines under the
radar to protect our precious exploit.

### Protecting binaries (there is a rootkit and agents as well)

1. Anti-debugging
2. Strip debugging symbols
3. Obfuscate strings
4. Compression
5. Encryption
6. Compile-time obfuscation

There are several ways you can protect your binaries from prying eyes. Anti-debugging, encryption, etc. The sad truth is that they can
all be defeated. Your goal is to frustrate the reverse engineer that is working on figuring out your warez. There is a great tool built
by one of my favorite hackers called the [MOVfuscator](https://github.com/xoreaxeaxeax/movfuscator). He used a hack on the X86 instruction 
by using MOV as a turing complete instruction. This is particular to X86 but I'd be using this for everything if I could. No one is going 
to sift through billions of MOV(src, dest) and extract meaning in their lifetime. 

For other architectures, I'd use something that obfuscates at the [intermediate representation of the 
language](https://groups.seas.harvard.edu/courses/cs153/2019fa/lectures/Lec06-LLVM.pdf) - LLVM. Since most modern compilers are written in 
LLVM, you can obfuscate them at the LLVM-IR (intermediate representation) level and even take a layered approach with more conventional 
protections like obfuscating strings, stripping, encryption, anti-debugging, packing - the world is your oyster.

Another protection to consider for fingerprinting are hashes. What if we could fake unique hashes for every exploit? @ me VirusTotal.
Repurpose [monomorph](https://github.com/DavidBuchanan314/monomorph) to randomize hashes and find quines/collisions by stuffing in 
random data. This is under the assumption that isn't a special hash in David's implementation and collisions/quines can be found
outside of its range.

### Bot roles

Each compromized node in the bot network will hold a particular role and be clustered in configurations with others. The goal is to have
a distributed infrastructure where killing one node/cluster doesn't take down the whole network. The entire bot network will communicate
in a P2P configuration of predefined states and will propagate exponentially as it distributes.

* Proxy
  * General purpose SOCKS
  * 3 required for a healthy cluster configuration
  * Exposed to clearnet
  * Relay for private tor network
* Command and control
  * C2 for all bots in the cluster
  * 1 required for a healthy cluster configuration
  * Communicates to other nodes over private Tor
  * Communicates over private tor to at most 2 other C2s
* Scanner
  * Gets subnet allocations from command and control
  * 1 required for a healthy cluster configuration
  * Reports vulnerable hosts to worker node over private Tor
* Worker
  * Launches exploit at vulnerable hosts found by scanner
  * General purpose worker
  * 1 required for a healthy cluster configuration
  * Ask C2 if reverse shell connected over private Tor (if not, marked invalid host in C2)

### Bot communication

In an effort to hide all communication from the public world and still use battle-hardened tools without reinventing the wheel - you
create your own private Tor by running a directory server [Bastet](https://blog.torproject.org/introducing-bastet-our-new-directory-authority/).

This can make all C2/bot comms happen over our private Tor for no exposure over the clearnet and no usual threat from mainstream Tor. 
The only clearnet comms exposed are those forwarded/relayed by proxy nodes with their port open.

### Launch configuration

Since we want this monster to be away from our name, image, and likeness - we will launch the initial exploit from a compromized machine
or anonymous VPS. As full configurations will not be available - this is the path to a healthy configuration.

Our first machine that is exploited will carry configurations for all nodes and be able to execute any of their actions. As the first
cluster is built, roles will be removed from the originators and the new will carry one less than their predecessor. When the first cluster
is complete - it will keep searching for new nodes. When one is found,the C2 will pass the compromized machine to a new C2 in another cluster
to distribute bots amongst clusters. With this configuration, the network will grow asynchronously out of leaf clusters and compartmentalize
comms over our private version of Tor.

When persistence is established, the bots download their implant from a common file-upload website that isn't likely to raise flags on a
network appliance. Once loaded, the implant does the following:

1. Hides the port the agent communicates on from the host.
2. Creates a working directory that is hidden from the host by using the defined prefix/suffix in implant.
3. Launches the agent and hides the process from the host.
4. Downloads toolset for role configuration
5. Executes role or waits for commands from its delegator

### Threat model

Now that we have a general picture of where this killchain is going - let's model some risks.

What is being modeled?

- Risk to attribution/deanonymization
- Discovery/takedown of hosts under control
- Means/methods protection
- Gateway from private Tor to main Tor
- Control panel on regular Tor through gateway from private
- Compromise of control panel
- Compromise of C2 node
- Compromise of Worker node
- Compromise of Scanner node
- Compromise of Proxy node
- Implant found and analyzed
- Identity leak
  - Metadata in tools
  - Initial connection to VPS (many ways to get for BitCoin/other crypto) or compromized machine (use Tor) for launch of exploit
  - Language style (just don't leave text or leave garbage text in another language like governments of the world)
- Least privilege
  - In the event a node is compromized, it should have least-privilege in terms of what it can do within the network
  - Only C2 nodes can look outside the cluster for other C2s
- Secure communication
  - Private Tor via private directory server
  - SOCKS exposure to clear only
  - Post-exploitation patching of protocol to keep others out
  - Post-exploitation scanning for other vulns to worry about
- Secure code
- Secure infrastructure
- Can be kept hidden unless physical access to box or actively checking disparities between what's reported by a host's kernel on your network
  vs what's going over the wire at the network appliance.
- Disaster recovery

#### Assumptions

* Can self propagate
* Can be kept anonymous if initial launch was anonymous
* Gateway from private Tor to main Tor is feasible via running a directory server
* C2s track state for cluster health

#### Threats

* Law enforcement
* Other hackers/security researchers
* Services like VirusTotal
* Others knowing identity
* Basically anything outside of your silent knowledge

#### Mitigations

* Buy a VPS over Tor with a crypto currency
* Compromise first host over Tor
* SAST scanning of code
* Fuzz binaries/panel + DAST
* Patch compromised systems
* Limit summoning the whole network
* Enable cluster self-healing by finding a new node when disconnected
* Obfuscate/encrypt binaries, enable anti-debugging features, pack to random hashes.
* Set up implant to hide all of our files, port traffic, processes, implant module from the host
* Terraform required infrastructure
* Don't leave behind text (strip binaries, comments, no textfiles on nodes)
* Harden infrastructure
* Regularly patch required infrastructure
* Strong authentication on Tor panel

#### Validation/measurable success

* Any indicators of compromise?
* Unrecognized ingress traffic to compromised nodes?
* Checking VirusTotal for our file hashes
* No arrests/warrants
* Infrastructure up and working properly
* Failed pentest on systems
* Can't reverse engineer binaries
* Systems updated
* Clusters rebuild as nodes go down
* Ability to limit summoning size to not reveal the whole network

## Implant

The implant will be a kernel module that will get inserted via kpatch or insmod after compromise. It's features include the following:

* Hide implant module from lsmod
* Hide processes from host
* Hide users from host
* Hide open ports from host
* Hide traffic based on hostname/IP
* Hide certain domains/IPs from network traffic
* Modify random/urandom to break cryptography
* Execute a command
  * Hide command with implant
  * Transmit stdout/stderr over the wire 
* Download files
  * Hide download process with implant
* Transmit files
  * Hide upload process with implant
* Elevate privileges of a command
* Update implant

That is it - the rest will simiply be executing commands on the host or dropping files/hiding them and their executions to suit our 
needs.

## Connection to C2

Each compromized node will download a generated binary with their own personal key into the private Tor network. This binary will
be configured to hit the private Tor directory server and join the botnet and inform it's cluster's C2.

## Super spreading

Your botnet is already growing at an exponential rate at the leaf clusters still being constructed but the infection rate isn't
big or growing fast enough for you. The exposure of proxies to the clearnet had an alternate purpose. Since they are scarce and
such a headache to find without paying, you submit each new bot to a proxy list website and let users spread it to other proxy
lists - exponential growth on top of exponential growth. Each connection to the proxy will be tossed the same exploit to grab
new Linux hosts.

## Observability/Monitoring

We need a dashboard/panel to manage and query our bots. This requires standing up a bit of infrastructure. We will need something
like Elastic or Splunk to eat logs from our compromised machines and keep track of their juicy details.

You settle on the following attributes being important:

* Bots
  * Last check in (no constant keepalives - dead silence until summoned)
  * Geolocation
  * Origination (Proxy honeypot or scanner/worker)
  * Max up
  * Max down
  * OS/Version
  * Num CPUs
  * Memory
  * CPU architecture/model info
  * GPU
  * GPU memory
  * Average GPU load
  * Average CPU load
  * Average memory usage
  * Average transmission rate
  * Average receive rate
  * Disk space
  * Vuln patched
  * Has persistent storage
  * Last updated
  * Orphaned (if all in cluster communicating with node go down)
  * Resolved domain
 
* Clusters
  * Last check in
  * Polygon of geolocation for map
  * Max up
  * Max down
  * Num CPUs
  * Average load
  * Average transmission rate
  * Average receive rate
  * Health
    * Status
    * Node state

### Log daemon deployment for bots

To deploy your log collectors to the bot nodes:

1. Send filebeat agents that call back to Elastic from C2
2. Put the binary in directory hidden by implant
3. Execute
4. Hide process with implant
5. Update role configuration to enable/hide agent every reboot.

### Storage

Our bots will likely have data we want to exfiltrate and will need a hefty amount of storage to do that. As we
want reliability and not failure on node takedowns - with crypto buy a BLOB store over Tor. Alternatively, find
a file-sharing website and use headless automation or their API to automate account registration so clusters
can have their own accounts. Important in this step is that usernames/passwords aren't sequential or identifiable. 
Either go full random or generate real-looking usernames/passwords in a uniformly random way.

Storage costs on BLOB stores are negligible.

## Common kernel modules between bot implants

To be the stealthiest spy there is, you need to modify a few default drivers and set up collections for data of 
interest.

* Webcam module
  * Modification of official linux kernel module
    * Don't enable activity light if possible
    * Don't report activity to OS
  * Official module removed when webcam requested, modified module inserted until inactive - then old reinserted.
* Microphone module
  * Modification of official linux kernel module
    * Don't enable activity light if possible
    * Don't report activity to OS
* Screen recorder
  * Ability to hijack video driver for recordings/multiple screens
* Keylogger
  * Ability to hijack all keyboards and log to separate files
* Mouse control
  * Ability to send mouse movements/actions to existing driver for GUI applications
* Networking
  * Ability to tap all comms/protocols of interest

### Common daemons between bots

All daemons have their logs ingested by filebeats or their warez uploaded to the BLOB stores.

1. Cookie stealer (all the browsers)
2. File/directory watcher
  - ARP table
  - Certs for SSL traffic
3. Shell history
4. Packet capture

## To be continued
