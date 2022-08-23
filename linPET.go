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

func colorize(colorized_string string) string {
    block_chars := []string{"╔", "═", "║", "╚", "╠"}
    for _, char := range block_chars {
        if strings.Contains(colorized_string, char) {
            colorized_string = fmt.Sprintf(strings.Replace(colorized_string, char, fmt.Sprint(cyan, char, reset), -1))
        }
    }
    return colorized_string
}


func IsReadable(fileName string) bool {
    file, err := os.Open(fileName)
    if err != nil {
        return false
    }
    defer file.Close()
    return true
}


func IsWritable(fileName string) bool {
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


func basic_info() {
  id := exec.Command("id")
  id_out := &bytes.Buffer{}
  id.Stdout = id_out
  id.Run()
  fmt.Println(colorize("╔═════ id"))
  fmt.Println(colorize("║"))
  fmt.Println(colorize("╚══ "), id_out)

  hostname := exec.Command("hostname")
  hostname_out := &bytes.Buffer{}
  hostname.Stdout = hostname_out
  hostname.Run()
  fmt.Println(colorize("╔═════ hostname"))
  fmt.Println(colorize("║"))
  fmt.Println(colorize("╚══ "), hostname_out)


}


func release() {
  uname_a := exec.Command("/usr/bin/uname", "-a")
  uname_a_out := &bytes.Buffer{}
  uname_a.Stdout = uname_a_out
  uname_a.Run()
  fmt.Println(colorize("╔═════ release"))
  fmt.Println(colorize("║"))
  fmt.Println(colorize("╚══ "), uname_a_out)

// kernal release with only one decimal to be used for kernal exploit suggestion.  
/*
  uname_r:= exec.Command("uname", "-r")
  uname_r_out := &bytes.Buffer{}
  uname_r.Stdout = uname_r_out
  uname_r.Run()

  no_dash := strings.Split(fmt.Sprintf("%s", uname_r_out), "-")
  release := (no_dash[0])
  no_period := strings.Split(release, ".")
  processed_release := (no_period[0] + "." + no_period[1])

  fmt.Println(processed_release)
  */

}

var vul_suid_check = []string{
"ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell", "atobm", "awk", "base32", "base64", "basenc", "bash", "bridge", "busybox", "bzip2", "capsh", "cat", "chmod", "choom", "chown", "chroot", "cmp", "column",
"comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter", "curl", "cut", "dash", "date", "dd", "dialog", "diff", "dig", "dmsetup", "docker", "dosbox", "ed", "efax", "emacs", "env", "eqn", "expand", "expect", "file", 
"find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie", "genisoimage", "gimp", "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight", "hping3", "iconv", "install", "ionice", "ip", "ispell", "jss", "join",
"jq", "jrunscript", "ksh", "ksshell", "kubectl", "ld.so", "less", "logsave", "look", "lua", "make", "mawk", "more", "mosquitto", "msgattrib" , "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime", "mv" , "nasm", "nawk", 
"nice", "nl", "nm", "nmap", "node", "nohup", "od", "openssl", "openvpn", "paste", "perf", "perl", "pg", "php", "pidstat", "pr", "ptx", "python", "readelf", "restic", "rev", "rlwrap", "rsync", "run-parts", "rview", "rvim", "sash", "scanmem", 
"sed", "setarch", "shuf", "soelim", "sort", "sqlite3", "ss", "ssh-keygen", "ssh-keyscan", "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac", "tail", "taskset", "tbl", "tclsh", "tee", "tftp", "tic", 
"time", "timeout", "troff", "ul", "unexpand", "uniq", "unshare", "unzip", "update-alternatives", "uudecode", "uuencode", "view", "vigr", "vim", "vimdiff", "vipw", "watch", "wc", "wget", "whiptail", "xargs", "xdotool", "xmodmap", "xmore",
"xxd", "xz", "yash", "zsh", "zsoelim",
}
var vul_suid = []string{}
func suid() {
  find_suid := exec.Command("/usr/bin/find", "/", "-perm", "/4000")
  find_suid_out := &bytes.Buffer{}
  find_suid.Stdout = find_suid_out
  find_suid.Run()
  fmt.Println(colorize("╔═════ Suid"))
  fmt.Println(colorize("║"))
  test := strings.Split(fmt.Sprintf("%s", find_suid_out), "\n")

  printed := false
  for _, dir := range test {
    test2 := strings.Split(dir, "/")
    test3 := fmt.Sprintf(test2[len(test2)-1])
    for _, bin := range vul_suid_check {
        if test3 == bin {
            vul_suid = append(vul_suid, dir)
            fmt.Println(colorize("╠══"),redBg, dir, reset)
            printed = true
        } 
    }
    if printed != true {
        fmt.Println(colorize("╠══"),dir)
    } 
    printed = false

  }
}


func guid() {
  find_guid := exec.Command("/usr/bin/find", "/", "-perm", "/6000")
  find_guid_out := &bytes.Buffer{}
  find_guid.Stdout = find_guid_out
  find_guid.Run()
  fmt.Println(colorize("╔═════ Guid"))
  fmt.Println(colorize("║"))
  test := strings.Split(fmt.Sprintf("%s", find_guid_out), "\n")
  for _, guid := range test {
    fmt.Println(colorize("╠══"), guid)
  }
}


func users() {
    file, err := os.Open("/etc/passwd")
    if err != nil {
      fmt.Println("what even the fuk")
    }
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

/*
var vul_cap_check = []string{
    "gdb", "node", "perl", "php", "python", "ruby", "rview", "rvim", "view", "vim", "vimdiff",
}
*/

func capabilites() {
  getcap := exec.Command("getcap", "-r", "/")
  getcap_out := &bytes.Buffer{}
  getcap.Stdout = getcap_out
  getcap.Run()
  fmt.Println(colorize("╔═════ capabilites"))
  fmt.Println(colorize("║"))
  test := strings.Split(fmt.Sprintf("%s", getcap_out), "\n")
  for _, cap := range test {
    fmt.Println(colorize("╠══"), cap)
  }
}



func weakpermissions() {
    checkread := []string{"/etc/shadow", "/etc/sudoers", "/root"}
    checkwrite := []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root"}
    readable := []string{}
    writable := []string{}

    for _, dir := range checkwrite {
        test_w := IsWritable(dir)
        if test_w == true {
            readable = append(readable, dir)
        }
    }
    for _, dir := range checkread {
        test_r := IsReadable(dir)
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

var python_paths = []string{}
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

        tmpfile := "/tmp/testfile"
        for _, dir := range real_python_paths{
            file, _ := os.Create(tmpfile)
            os.Chmod(tmpfile, 0777)
            _, _ = file.Write([]byte(fmt.Sprintf(dir + ` -c 'import sys;print("\n".join(sys.path))'`)))
            defer file.Close()

            id := exec.Command("/bin/bash", tmpfile)
            id_out := &bytes.Buffer{}
            id.Stdout = id_out
            id.Run()
            id_out2 := fmt.Sprintf("%s", id_out)
            id_out3 := strings.Split(id_out2, "\n")

            for _, dir := range id_out3 {
                if dir == "" {
                    continue
                }
                if exists(dir) != true {
                    fmt.Println(colorize("╠══ "), dir, "-- does not exist")
                    continue
                }
                if IsWritable(dir) == true {
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

                    if IsWritable(path) {
                        fmt.Println(colorize("║      ╚══ "), path)
                    }
                }
            }
        }
    } // first if
} // func end

func main() {
  basic_info()
  release()
  users()
  weakpermissions()
  useful_software()
  fmt.Println()
  py_path_hijack()
  fmt.Println()
  suid()
  fmt.Println()
  guid()
  fmt.Println()
  capabilites()
  fmt.Println()
}