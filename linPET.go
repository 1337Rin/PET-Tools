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
)
 
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


func basic_info() {
  id := exec.Command("id")
  id_out := &bytes.Buffer{}
  id.Stdout = id_out
  id.Run()
  fmt.Println("╔═════ id")
  fmt.Println("║")
  fmt.Printf("╚══ %s", id_out)
  fmt.Println()

  hostname := exec.Command("hostname")
  hostname_out := &bytes.Buffer{}
  hostname.Stdout = hostname_out
  hostname.Run()
  fmt.Println("╔═════ hostname")
  fmt.Println("║")
  fmt.Printf("╚══ %s", hostname_out)
  fmt.Println()


}


func release() {
  uname_a := exec.Command("/usr/bin/uname", "-a")
  uname_a_out := &bytes.Buffer{}
  uname_a.Stdout = uname_a_out
  uname_a.Run()
  fmt.Println("╔═════ release")
  fmt.Println("║")
  fmt.Printf("╚══ %s", uname_a_out)
  fmt.Println()

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


func suid() {
  find_suid := exec.Command("/usr/bin/find", "/", "-perm", "/4000")
  find_suid_out := &bytes.Buffer{}
  find_suid.Stdout = find_suid_out
  find_suid.Run()
  fmt.Println("╔═════ Suid")
  fmt.Println("║")
  fmt.Println(find_suid_out)
  fmt.Println()
}


func guid() {
  find_guid := exec.Command("/usr/bin/find", "/", "-perm", "/6000")
  find_guid_out := &bytes.Buffer{}
  find_guid.Stdout = find_guid_out
  find_guid.Run()
  fmt.Println("╔═════ Guid")
  fmt.Println("║")
  fmt.Println(find_guid_out)
  fmt.Println()
}


func users() {
    file, err := os.Open("/etc/passwd")
    if err != nil {
      fmt.Println("what even the fuk")
    }
    defer file.Close()

    fmt.Println("╔═════ users")
    fmt.Println("║")

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        bash := strings.Contains(scanner.Text(), "bash")
        dash := strings.Contains(scanner.Text(), "dash")
        sh := strings.Contains(scanner.Text(), "sh")
        if bash || dash || sh {
          fmt.Println("╠══", scanner.Text())
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
  fmt.Println("╔═════ capabilites")
  fmt.Println("║")
  fmt.Println(getcap_out)
  fmt.Println()
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
      fmt.Println("╔═════ Readable files and directorys")
      fmt.Println("║")
      fmt.Println("╚══ ", readable)
      fmt.Println()
    }
    if len(writable) != 0 {
      fmt.Println("╔═════ writable files and directorys")
      fmt.Println("║")
      fmt.Println("╚══ ", writable)
      fmt.Println()
    }
}

func useful_software(){
    files, _ := ioutil.ReadDir("/usr/bin")
    python_paths := []string{}
    fmt.Println("╔═════ useful software")
    fmt.Println("║")
    for _, file := range files {
        if strings.Contains(file.Name(), "python") {
            if strings.Contains(file.Name(), "config") {
                continue
            }
            fmt.Print("╠══ /usr/bin/", file.Name(), "\n")
            python_path := fmt.Sprintf("%s", "/usr/bin/" + file.Name())
            python_paths = append(python_paths, python_path)

        } else if file.Name() == "go" {
            fmt.Print("╠══ /usr/bin/", file.Name(), "\n")
        } else if file.Name() == "gcc" {
            fmt.Print("╠══ /usr/bin/", file.Name(), "\n")
        } else if file.Name() == "base64" {
            fmt.Print("╠══ /usr/bin/", file.Name(), "\n")
        } else if file.Name() == "nc" {
            fmt.Print("╠══ /usr/bin/", file.Name(), "\n")
        } else {
            continue
        }
    }
    fmt.Println()
}


func main() {
  basic_info()
  release()
  users()
  weakpermissions()
  useful_software()
  suid()
  guid()
  capabilites()
}