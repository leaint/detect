package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Flags() | log.Llongfile)
}

type config struct {
	ipf       *os.File
	timeout   time.Duration
	batchsize int
	count     int
	gap       time.Duration
}

var resp []byte = []byte{2, 0, 0, 0}

func initConfig() config {
	fname := flag.String("f", "ip.txt", "ip address file to test")
	batchsize := flag.Int("n", 5, "how many goroutines to use. >= 1")
	count := flag.Int("c", 1, "how many packets for each ip address to send. >= 1")
	timeout := flag.Int64("w", 1000, "a timeout for send or recv packet, in milliseconds. recommend > 400")
	gap := flag.Int64("g", 1000, "a gap time for next packet to send, in milliseconds.")

	flag.Parse()

	if *batchsize < 1 {
		*batchsize = 1
	}

	if *count < 1 {
		*count = 1
	}

	var f *os.File
	if *fname == "-" {
		f = os.Stdin
	} else {

		fi, err := os.OpenFile(*fname, os.O_RDONLY, os.ModePerm)
		if err != nil {
			panic(err)
		}

		f = fi
	}

	return config{
		batchsize: *batchsize,
		ipf:       f,
		timeout:   time.Duration(*timeout) * time.Millisecond,
		count:     *count,
		gap:       time.Duration(*gap) * time.Millisecond,
	}
}

func sendS(address string, timeout time.Duration, gap time.Duration, count int, buf []byte) []int {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		log.Println(err)
		return nil
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer conn.Close()

	pings := make([]int, count)

	for i := 0; i < count; i++ {
		conn.SetWriteDeadline(time.Now().Add(timeout))
		t1 := time.Now()
		_, err = conn.Write(packet)

		if err != nil {
			log.Println(err)

			continue
		}

		conn.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := conn.ReadFromUDP(buf[:])
		t2 := time.Now()
		if err != nil {
			if e, ok := err.(net.Error); !(ok && e.Timeout()) {
				log.Println(err)
			}
			continue
		}

		// 由于收到的包可能是前面发送包的回应，所以可能出现延时非常小的值出现，
		// 伴随这种现象同时出现的是丢包率不为零，增加等待时间可以减少这种情况的出现
		if n > len(resp) && bytes.Equal(buf[:len(resp)], resp) {
			pings[i] = int(t2.Sub(t1).Milliseconds())
		}
		if count-i > 1 {
			time.Sleep(gap)
		}
	}

	return pings
}

func main() {

	conf := initConfig()

	rd := bufio.NewScanner(conf.ipf)

	addr := make(chan string, conf.batchsize)

	var wait sync.WaitGroup

	for i := 0; i < conf.batchsize; i++ {
		wait.Add(1)
		go func(ch chan string) {
			defer wait.Done()
			var buf [1024]byte

			for address := range ch {
				pings := sendS(address, conf.timeout, conf.gap, conf.count, buf[:])
				if len(pings) > 0 {

					avgtime := 0
					received := 0

					for _, p := range pings {
						if p > 0 {
							avgtime += p
							received++
						}
					}

					if received > 0 {
						avgtime /= received
					}

					fmt.Printf("%s\t%d%%\t%dms\n", address, received*100/len(pings), avgtime)
				}
			}
		}(addr)
	}

	for rd.Scan() {

		address := rd.Text()

		if s := strings.Trim(address, "\n"); len(s) > 0 {
			addr <- s
		}
	}

	tr := conf.batchsize
	for len(addr) != 0 && tr > 0 {
		tr--
		time.Sleep(conf.timeout)
	}

	close(addr)
	wait.Wait()
}
