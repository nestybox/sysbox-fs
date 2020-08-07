
// sysboxfs log parser

package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

func parseTrans(infile string, transMap map[int][]int) error {

	file, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("failed to read file %s: %v\n", infile, err)
		}

		// parse Uid=<num>
		re := regexp.MustCompile(`Uid=[0-9]+`)
		token := re.Find(line)

		if token == nil {
			continue
		}

		// convert Uid string to int
		uidStr := string(token)
		uidStr = strings.Trim(uidStr, "Uid=")
		uid64, err := strconv.ParseInt(uidStr, 0, 32)
		if err != nil {
			return fmt.Errorf("failed to convert %s to int: %v\n", uidStr, err)
		}
		uid := int(uid64)

		// Add Uid to map (if not present already)
		if _, found := transMap[uid]; !found {
			transMap[uid] = []int{}
		}

		// parse ID=<hex>
		re = regexp.MustCompile(`ID=0x[0-9a-f]+`)
		token = re.Find(line)
		if token == nil {
			continue
		}

		// convert ID string to int
		idStr := string(token)
		idStr = strings.Trim(idStr, "ID=")
		id64, err := strconv.ParseInt(idStr, 0, 32)
		if err != nil {
			return fmt.Errorf("failed to convert %s to int: %v\n", idStr, err)
		}
		id := int(id64)

		// Add ID to list of IDs for Uid
		ids, found := transMap[uid]
		if !found {
			return fmt.Errorf("did not find uid %d in transaction map!", uid)
		}
		ids = append(ids, id)
		transMap[uid] = ids
	}

	return nil
}

func uidTransParser(data []byte, uid int, ids []int, wg *sync.WaitGroup, errch chan error) {

	defer wg.Done()

	// create output file
	outfile := fmt.Sprintf("uid_%d", uid)
	outf, err := os.Create(outfile)
	if err != nil {
		errch <- err
		return
	}
	defer outf.Close()

	// start parsing
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		for _, id := range ids {
			token := fmt.Sprintf("ID=%#x", id)
			match, _ := regexp.MatchString("\\b"+token+"\\b", line)
			if match {
				_, err := outf.WriteString(line + "\n")
				if err != nil {
					errch <- fmt.Errorf("failed to write to file %s: %v", outfile, err)
					return
				}
			}
		}
	}
}

func dumpTrans(infile string, transMap map[int][]int) error {
	var wg sync.WaitGroup

	// read the file into mem; it will then be parsed concurrently
	inData, err := ioutil.ReadFile(infile)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", infile, err)
	}

	errch := make(chan error, len(transMap))

	// dump transactions per uid
	for uid, ids := range transMap {
		wg.Add(1)
		go uidTransParser(inData, uid, ids, &wg, errch)
	}

	wg.Wait()

	select {
	case err := <-errch:
		return err
	default:
	}

	return nil
}

func usage() {
	fmt.Printf("%s <filename>\n", os.Args[0])
}

func main() {

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	filename := os.Args[1]

	// maps container uid -> list of transactions associated with that container
	transMap := make(map[int][]int)

	if err := parseTrans(filename, transMap); err != nil {
		fmt.Printf("Failed to parse file %s: %v", filename, err)
		os.Exit(1)
	}

	// XXX: for debug
	// for uid, ids := range transMap {
	// 	fmt.Printf("uid %d: ", uid)
	// 	for _, id := range ids {
	// 		fmt.Printf("%#x ", id)
	// 	}
	// 	fmt.Printf("\n")
	// }

	if err := dumpTrans(filename, transMap); err != nil {
		fmt.Printf("Failed to dump transactions: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Done.\n")
}
