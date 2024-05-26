# Nahamcon Challenge: Jack Be

This challenge from Nahamcon 2024 CTF is of topic category `misc` and focuses on privilege escalation within Linux (medium difficulty).
The challenge text was given as:
> Wow! Jack is trying to learn one of the hottest new programming languages!!
> And on top of that, he wants you to learn it too! He has given you access to his development box. So generous of him! He said, "just don't hack it, please."
> Escalate your privileges and retrieve the contents of the /root/flag.txt file. 

> `Password is "userpass"`
> `ssh -p 31468 user@challenge.nahamcon.com`

## Enumeration

After logging into the box, we are user `user`:

```console
$ whoami
user
```

Checking `sudo -l` shows that we can run a specific command as user `jack`:

```console
$ sudo -l
(jack) NOPASSWD: /usr/bin/nimble run
```

`nimble` is the default package manager for the programming language `nim` and allows to create, install, and run nim-based packages. Due to the challenge hints, it is quite likely, that this is our entry point to full privilege escalation.

## Exploitation

Since we can only run nimble packages as jack, our goal is to craft such a package whose code then allows us to execute further commands.

There are generally two easy ways to let nimble execute arbitrary commands:

1) Create a nim program that itself executes system commands. An example is provided below:

```nim
import osproc

var result = execProcess("whoami")
echo result
```

2) Another option is, to execute system commands provided in the nimble package configuration file. This can be done by forcing nimble to run commands `before build` or `after build` with `exec`. An example is illustrated below:

``` bash
# other settings and package info
# ...

# before package is built
before build:
  echo "before build"
  exec "whoami"

# after package is built
after build:
  echo "after build"
  exec "whoami"
```

As we have the choice, we choose option one and create a package. Therefore, first, `nimble` can be used to set up a valid empty package with `nimble init`. To avoid any write permission issues later, a new folder within `/tmp` was chosen. Typically, one has to set a name, some description, and a type.   
After the package is created, one sees a nimble configuration file `[project name].nimble` and a `src` folder with a hello world nim source.   
Next, the source code has to be changed to our system command in nim. To verify the procedure, we choose the example code above.
Then the package can be build. It is no problem, that we can only run `run` as this indirectly invokes any needed build processes.

```console
$ cd /tmp/[project folder]
$ sudo -u jack /usr/bin/nimble run
...
...
jack
```
As expected, the compiled program is run after compilation as user `jack`. From here, another enumeration phase has to be started as we do not know what rights jack has. In principle, we could spawn an explicit shell to do so but will keep it simple here. Just running `sudo -l` for jack shows:
```
(root) NOPASSWD: /usr/bin/nimble install *
```

Apparently, `jack` can let nimble install packages as root. Unfortunately, `install` does not run a package, but only creates the binary. Hence, we have to create a second package for jack and use option two to run system commands.   
Again, within `/tmp` we create a new folder, initialize a new package and edit the configuration file to:

``` bash
# other settings and package info
# ...

# after package is built
after build:
  exec "cat /root/flag.txt"
```

At this point, the source code of package 2 does not matter anymore. However, since we are still `user` and avoided unnecessary reverse or spawned shell environments, we have to run `jack`'s command through an adjusted version of package one. An example for the package source is given below:

```nim
import osproc

var result = execProcess("cd /tmp/[project two] && sudo /usr/bin/nimble install --silent --accept")
echo result
```

The command first sets the working directory as the package folder and then runs our nimble install as root. Note, that after compilation, the configuration file triggers the actual system command.

After everything is set up, we only have to run the following commands as `user`:

```console
$ cd /tmp/[project folder]
$ sudo -u jack /usr/bin/nimble run
...
... // package one is build and run as "jack"
... // when run, package one installs package two as "root"
... // after compilation, the system commands are run as "root"
flag{7e8aee...9776ada}
```

This chain of privileged executions of nimble led to arbitrary commands as root, without the need of spawned shells.