package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// This function is used for reading original URLs from a text file.
func readURLFromFile(filePath string, numOfURLs uint) ([]string, error) {

	fmt.Printf(">>> Reading URL list %s ...\n\n", filePath)

	oriURLs := []string{}

	fi, err := os.Open(filePath)

	if err != nil {

		fmt.Printf("Error: %s\n", err)
		return nil, err
	}
	defer fi.Close()

	br := bufio.NewReader(fi)

	var i uint
	for i = 0; ; i++ {

		a, _, c := br.ReadLine()
		if c == io.EOF || i == numOfURLs {

			break
		}

		if string(a) == "" {

			continue
		}

		oriURLs = append(oriURLs, string(a))
	}

	fmt.Printf("    %d URLs are loaded!\n\n", len(oriURLs))

	return oriURLs, nil
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

// This function is used for pre-processing the list of "malicious" URLs, i.e.,
// obtaining URL patterns (decompositions).
func getAllUniquePatterns(oriURLs []string) []string {

	fmt.Printf(">>> Computing unique URL patterns (decompositions) ...\n\n")

	uniquePatterns := []string{}

	tempMap := make(map[string]int)

	for i := 0; i < len(oriURLs); i++ {

		curOriURL := oriURLs[i]

		patterns, err := generatePatterns(curOriURL)

		// simply skip a url that cannot obtain valid patterns via GSB api
		if err != nil {
			continue
		}

		for _, p := range patterns {
			tempMap[p] = 1
		}
	}

	for k := range tempMap {
		uniquePatterns = append(uniquePatterns, k)
	}

	fmt.Printf("    %d unique URL patterns are obtained!\n\n", len(uniquePatterns))

	return uniquePatterns
}

// This function is used for computing SHA-256 hashs, extracting 32-bit hash
// prefixs (short hash), and finally inserting them into an Inverted Index
// (key: hash prefix, value: decomposited URLs that share the hash prefix).
func buildShortHashIndex(uniquePatterns []string, bitlength int) map[string][]string {

	// fmt.Printf(">>> Building inverted index (key: hash prefix, value: decomposited URLs that share the hash prefix) ...\n\n")

	shortHashIndex := make(map[string][]string)

	// numOfUniquePatterns := len(uniquePatterns)

	for _, up := range uniquePatterns {

		hash := hashFromPattern(up)

		hex := fmt.Sprintf("%x", ([]byte(hash)[0:4]))
		binary, _ := strconv.ParseUint(hex, 16, 32)
		sh := fmt.Sprintf("%032b", binary)[0:bitlength]
		//fmt.Printf("256-bit hash:  %x\n32-bit prefix: %s, value: %s\n", hash, sh, up)

		urls, ok := shortHashIndex[sh]
		if ok {

			urls = append(urls, up)
			shortHashIndex[sh] = urls
		} else {

			shortHashIndex[sh] = []string{up}
		}

		// if ctr != 0 && ctr%(numOfUniquePatterns/10) == 0 {

		// 	fmt.Printf("    %d %% done ...\n", ctr*100/numOfUniquePatterns)
		// }
	}

	// fmt.Printf("    100 %% done \n\n")
	return shortHashIndex
}

func testCollisionByURL(index map[string][]string) {

	var qURL string

	fmt.Printf(">>> Testing collisions by a given URL ...\n")

	for {
		fmt.Println("\nPlease input a URL: (q - quit)")

		fmt.Scanln(&qURL)

		if qURL == "q" || qURL == "quit" {

			fmt.Println("Bye!")
			break
		}

		fmt.Println("\nRe-identified URLs:")

		hashes, err := generateHashes(qURL)
		if err != nil {

			log.Fatal("Come with fatal,exit with 1 \n")
		}

		hasCollision := false

		for k := range hashes {

			sh := fmt.Sprintf("%x", ([]byte(k))[0:4])

			// output the matched URLs (decompositions)
			urls, ok := index[sh]
			if ok {

				hasCollision = true
				for _, url := range urls {
					fmt.Println("   ", url)
				}
			}
		}

		if !hasCollision {
			fmt.Print("    No collision found!\n")
		}
	}
}

func analyzeShortHashIndex(index map[string][]string) {

	fmt.Printf(">>> Analyzing prefix index ...\n")

	numOfMatchesMap := make(map[int]int)

	for k := range index {

		numOfMatches := len(index[k])

		ctr, ok := numOfMatchesMap[numOfMatches]
		if ok {
			ctr++
			numOfMatchesMap[numOfMatches] = ctr
		} else {

			numOfMatchesMap[numOfMatches] = 1
		}
	}

	// fmt.Println("\n    Done! key - #matches, value - #prefixs")
	fmt.Println("   ", numOfMatchesMap)
	fmt.Println()
	sum := 0
	valuesum := 0
	for k, v := range numOfMatchesMap {
		sum = sum + k*v
		valuesum = valuesum + v
	}
	fmt.Println("Expectation is ", sum/valuesum)
	fmt.Println()
}

func unique(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, found := keys[entry]; !found {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func findDups(arr []string) {
	//Create a   dictionary of values for each element
	dict := make(map[string]int)
	for _, ele := range arr {
		dict[ele] = dict[ele] + 1
		if dict[ele] > 1 {
			fmt.Println(ele)
		}
	}
}

func eCrimeDataNorm() {
	const UintMax = ^uint(0)

	filePath := flag.String("p", "../eCrimeExchange/phish15-19_4300k.txt", "input file path")
	numOfURLs := flag.Uint("n", UintMax, "number of URLs")

	flag.Parse()

	oriURLs, err := readURLFromFile(*filePath, *numOfURLs)

	if err != nil {

		fmt.Printf("Error: %s\n", err)
		return
	}

	// Step 1: Canonicalize URLs and write to "canonicalized.txt"
	for i := 0; i < len(oriURLs); i++ {
		// !!!!!! refined source code of urls.go to remove the schemes
		oriURLs[i], _ = canonicalURL(oriURLs[i])
	}

	writeLines(oriURLs, "./canonicalized.txt")
	// findDups(oriURLs)

	// Step 2: Dedup the canonicalized URLs and write to "canondeduped.txt"
	uniqueURLs := unique(oriURLs)
	fmt.Printf("    %d unique URLs are obtained!\n\n", len(uniqueURLs))

	writeLines(uniqueURLs, "./canondeduped.txt")

	// Step 2: Find unique decomposed URL prefix/suffix expressions and its corresponding hash prefixes,
	// build an index of hashprefix -> Array[decompositions], write to "hashprefix.json"
	uniquePatterns := getAllUniquePatterns(oriURLs)
	writeLines(uniquePatterns, "./decomposed.txt")
	shortHashIndex := buildShortHashIndex(uniquePatterns, 32) // bit length should be less than or equal to 32
	jsonString, err := json.MarshalIndent(shortHashIndex, "", "    ")
	_ = ioutil.WriteFile("hashprefix3.json", jsonString, 0644)
}

func readJsontoMap(str string) map[string][]string {
	jsonFile, err := os.Open(str)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened " + str)
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	shortHashIndex := make(map[string][]string)
	if err := json.Unmarshal(byteValue, &shortHashIndex); err != nil {
		fmt.Println(err)
	}
	return shortHashIndex
}

func readSQLite() []string {
	database, _ := sql.Open("sqlite3", "./gsb_v4.db")
	rows, _ := database.Query("SELECT hex(value) FROM hash_prefix WHERE platform_type = 'ANY_PLATFORM'")

	hashprefixstrings := []string{}
	var hashprefix string
	for rows.Next() {
		rows.Scan(&hashprefix)
		hashprefixstrings = append(hashprefixstrings, strings.ToLower(hashprefix))
	}
	fmt.Printf("GSB hash prefix sqlite db has %d items.\n", len(hashprefixstrings))
	return hashprefixstrings
}

func gsbmatchecrime() {
	gsbhashprefixes, _ := readURLFromFile("./GSBhashprefixes.txt", ^uint(0))
	ecrimemaps := readJsontoMap("hashprefix.json")
	cnt := 0
	matchedkeys := []string{}
	for i := 0; i < len(gsbhashprefixes); i++ {
		item := gsbhashprefixes[i]
		_, ok := ecrimemaps[item]
		if ok {
			cnt++
			matchedkeys = append(matchedkeys, item)
		}
	}
	fmt.Printf("%d of 1636843 GSB URLs (1117196 GSB hash prefixes) match the eCrimeX Json file results.\n", cnt)

	// subset := make(map[string][]string)
	subset := []string{}
	for _, key := range matchedkeys {
		// subset[key] = ecrimemaps[key]
		subset = append(subset, "microsoft-edge:http://"+ecrimemaps[key][0])
	}
	// jsonString, _ := json.MarshalIndent(subset, "", "    ")
	// _ = ioutil.WriteFile("gsbmatchecrime.json", jsonString, 0644)
	writeLines(subset, "./smartscreentest.txt")
}

func ecrimematchegsb() {
	gsbhashprefixes, _ := readURLFromFile("./GSBhashprefixes.txt", ^uint(0))

	// ecrimemaps := readJsontoMap("hashprefix.json")
	ecrime, _ := readURLFromFile("./okstatus3.txt", ^uint(0))
	uniquePatterns := getAllUniquePatterns(ecrime)
	ecrimemaps := buildShortHashIndex(uniquePatterns, 32)

	set := make(map[string]bool)
	for _, v := range gsbhashprefixes {
		binary, _ := strconv.ParseUint(v, 16, 32)
		sh := fmt.Sprintf("%032b", binary)[0:32]
		set[sh] = true
	}

	cnt := 0
	matchedkeys := []string{}
	for key := range ecrimemaps {
		if set[key] == true {
			cnt++
			matchedkeys = append(matchedkeys, key)
		}
	}
	fmt.Printf("%d of 2140183 eCrimeX URLs (5472965 GSB hash prefixes) match the GSB hash prefix results.\n", cnt)

	subset := make(map[string][]string)
	for _, key := range matchedkeys {
		subset[key] = ecrimemaps[key]
	}
	jsonString, _ := json.MarshalIndent(subset, "", "    ")
	_ = ioutil.WriteFile("ecrimematchegsb.json", jsonString, 0644)
}

func shallalisttrack() {
	shallalist, _ := readURLFromFile("./alldomains.txt", ^uint(0))
	gsbhashprefixes, _ := readURLFromFile("./GSBhashprefixes.txt", ^uint(0))
	gsbhashprefixesset := make(map[string]bool)
	for _, v := range gsbhashprefixes {
		gsbhashprefixesset[v] = true
	}

	// Step 1: Canonicalize URLs
	for i := 0; i < len(shallalist); i++ {
		// !!!!!! refined source code of urls.go to remove the schemes
		shallalist[i], _ = canonicalURL(shallalist[i])
	}
	fmt.Printf("    %d items from shallalist are obtained!\n\n", len(shallalist))

	uniqueItems := unique(shallalist)
	fmt.Printf("    %d unique items are obtained!\n\n", len(uniqueItems))

	eCrimeIndex := readJsontoMap("hashprefix.json")
	suspiciousList := []string{}
	verifyList := []string{}
	for i := 0; i < len(uniqueItems); i++ {
		// !!!!!! refined source code of urls.go to remove the schemes
		hitcnt := 0
		verifycnt := 0
		hashes, _ := generateHashes(uniqueItems[i])
		for hash := range hashes {
			sh := fmt.Sprintf("%x", ([]byte(hash))[0:4])

			if gsbhashprefixesset[sh] == true {
				hitcnt++
			}
			_, ok := eCrimeIndex[sh]
			if ok {
				verifycnt++
			}
		}
		if hitcnt == 1 {
			suspiciousList = append(suspiciousList, uniqueItems[i])
		}
		if verifycnt == 1 {
			verifyList = append(verifyList, uniqueItems[i])
		}
	}
	writeLines(suspiciousList, "./suspicious.txt")
	writeLines(verifyList, "./verify.txt")
}

func alexaDataNorm() {
	const UintMax = ^uint(0)

	filePath := flag.String("p", "./top-1m.csv", "input file path")
	numOfURLs := flag.Uint("n", UintMax, "number of URLs")

	flag.Parse()

	sites, err := readURLFromFile(*filePath, *numOfURLs)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	// Step 1: Canonicalize URLs and write to "canonicalized.txt"
	for i := 0; i < len(sites); i++ {
		site := strings.Split(sites[i], ",")[1]
		// !!!!!! refined source code of urls.go to remove the schemes
		sites[i], _ = canonicalURL(site)
	}

	// Step 2: Find unique decomposed URL prefix/suffix expressions and its corresponding hash prefixes,
	// build an index of hashprefix -> Array[decompositions], write to "hashprefix.json"
	uniquePatterns := getAllUniquePatterns(sites)
	shortHashIndex := buildShortHashIndex(uniquePatterns, 32)
	jsonString, err := json.MarshalIndent(shortHashIndex, "", "    ")
	_ = ioutil.WriteFile("alex.json", jsonString, 0644)
}

// Item : json object to Golang struct
type Item struct {
	Faviconurl     string `json:"favicon_url"`
	Pagetransition string `json:"page_transition"`
	Title          string `json:"title"`
	Urlhistory     string `json:"url"`
	Clientid       string `json:"client_id"`
	Timeusec       int64  `json:"time_usec"`
}

func browsingHistoryNorm() {
	jsonFile, err := os.Open("BrowserHistory.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened ")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var items []Item
	json.Unmarshal(byteValue, &items)

	historydup := []string{}
	for _, ele := range items {
		historydup = append(historydup, ele.Urlhistory)
	}

	history := unique(historydup)
	fmt.Printf("Total number of %d browsing history items.\n\n", len(history))

	for i := 0; i < len(history); i++ {
		// !!!!!! refined source code of urls.go to remove the schemes
		history[i], _ = canonicalURL(history[i])
	}

	gsbhashprefixes, _ := readURLFromFile("./GSBhashprefixes.txt", ^uint(0))
	gsbhashprefixesset := make(map[string]bool)
	for _, v := range gsbhashprefixes {
		gsbhashprefixesset[v] = true
	}

	hits := []string{}
	for i := 0; i < len(history); i++ {
		// !!!!!! refined source code of urls.go to remove the schemes
		hitcnt := 0
		hashes, _ := generateHashes(history[i])
		for hash := range hashes {
			sh := fmt.Sprintf("%x", ([]byte(hash))[0:4])
			if gsbhashprefixesset[sh] == true {
				hitcnt++
			}
		}
		if hitcnt >= 1 {
			hits = append(hits, history[i])
		}
	}

	writeLines(hits, "historyhits-Leixu.txt")

	// uniquePatterns := getAllUniquePatterns(hits)
	// shortHashIndex := buildShortHashIndex(uniquePatterns)
	// jsonString, err := json.MarshalIndent(shortHashIndex, "", "    ")
	// _ = ioutil.WriteFile("historyindex.json", jsonString, 0644)
}

func collisionTest() {
	gsbhashprefixes, _ := readURLFromFile("./GSBhashprefixes.txt", ^uint(0))
	gsbhashprefixesset := make(map[string]bool)
	for _, v := range gsbhashprefixes {
		gsbhashprefixesset[v] = true
	}
	// potentialcollision, _ := readURLFromFile("./onlinetest3.txt", ^uint(0))
	// for _, item := range potentialcollision {
	// 	hashes, _ := generateHashes(item)
	// 	for hash := range hashes {
	// 		sh := fmt.Sprintf("%x", ([]byte(hash))[0:4])
	// 		if gsbhashprefixesset[sh] == true {
	// 			fmt.Println(item + ", " + hashes[hash] + ", " + sh)
	// 		}
	// 	}
	// }
	jsonFile, err := os.Open("BrowserHistory-Louis.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened ")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var items []Item
	json.Unmarshal(byteValue, &items)

	historydup := []string{}
	for _, ele := range items {
		historydup = append(historydup, ele.Urlhistory)
	}

	history := unique(historydup)
	for _, item := range history {
		hashes, _ := generateHashes(item)
		for hash := range hashes {
			sh := fmt.Sprintf("%x", ([]byte(hash))[0:4])
			if gsbhashprefixesset[sh] == true {
				fmt.Println(item + ", " + hashes[hash] + ", " + sh)
			}
		}
	}
}

func collisionTest2() {
	ecrimeprefixes := readJsontoMap("hashprefix.json")
	// shallalist, _ := readURLFromFile("./shallalist.txt", ^uint(0))

	jsonFile, err := os.Open("BrowserHistory.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened ")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var items []Item
	json.Unmarshal(byteValue, &items)

	historydup := []string{}
	for _, ele := range items {
		historydup = append(historydup, ele.Urlhistory)
	}

	history := unique(historydup)

	// cnt := 0
	// matchShalla := []string{}
	// for i := 0; i < len(shallalist); i++ {
	// 	item := shallalist[i]
	// 	hashes, _ := generateHashes(item)
	// 	for hash := range hashes {
	// 		sh := fmt.Sprintf("%x", ([]byte(hash))[0:4])
	// 		_, ok := ecrimeprefixes[sh]
	// 		if ok == true {
	// 			cnt++
	// 			matchShalla = append(matchShalla, item)
	// 		}
	// 	}
	// }
	// fmt.Printf("%d matched.\n", cnt)

	cnt := 0
	matchHistory := []string{}
	for i := 0; i < len(history); i++ {
		item := history[i]
		hashes, _ := generateHashes(item)
		for hash := range hashes {
			sh := fmt.Sprintf("%x", ([]byte(hash))[0:4])
			_, ok := ecrimeprefixes[sh]
			if ok == true {
				cnt++
				matchHistory = append(matchHistory, item+", "+hashes[hash]+", "+sh)
			}
		}
	}
	fmt.Printf("%d matched.\n", cnt)
	writeLines(matchHistory, "groundtruth.txt")
}

func uniqueHistoryHashPrefixes() {
	jsonFile, err := os.Open("BrowserHistory.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Successfully Opened ")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var items []Item
	json.Unmarshal(byteValue, &items)

	historydup := []string{}
	for _, ele := range items {
		historydup = append(historydup, ele.Urlhistory)
	}
	history := unique(historydup)

	uniquePatterns := getAllUniquePatterns(history)
	shortHashIndex := buildShortHashIndex(uniquePatterns, 32)
	// jsonString, err := json.MarshalIndent(shortHashIndex, "", "    ")
	// _ = ioutil.WriteFile("browsehashprefixes.json", jsonString, 0644)
	analyzeShortHashIndex(shortHashIndex)
}

func main() {
	// Module 1: Normalize (dedup) phishing URLs from eCrimeX and write down results
	// eCrimeDataNorm()

	// Module 2: Load Json file of prefix -> decomposition for eCrimeX's data and analyze the results
	ecrimedecomposed, _ := readURLFromFile("./decomposed.txt", ^uint(0))
	shortHashIndex := buildShortHashIndex(ecrimedecomposed, 32)
	analyzeShortHashIndex(shortHashIndex)
	// for i := 18; i <= 32; i = i + 2 {
	// 	fmt.Printf("Hash prefix bit length is %d\n", i)
	// 	shortHashIndex := buildShortHashIndex(ecrimedecomposed, i)
	// 	analyzeShortHashIndex(shortHashIndex)
	// }

	// Module 3: Load Json file of prefix -> decomposition for eCrimeX's data and test collision for mannually input results
	// testCollisionByURL(readJsontoMap("hashprefix.json"))

	// Module 4: Read SQLite db of GSB hash prefixes and write down line by line to a text file
	// writeLines(readSQLite(), "./GSBhashprefixes.txt")

	// Module 5: Calculate how many of 1117196 GSB hash prefixes match the eCrimeX Json file results
	// Upper bound & Lower bound (w. & w.o. URLs with same hash prefixes)
	// Also to analyze all the hash prefixes of GSB that we can ``translate'' to URLs with eCrimeX data (observe patterns, all domains, aka how may ends with '/'?)
	// gsbmatchecrime()

	// Module 6: Calculate how many of 2140183 eCrime URLs match the GSB hash prefixes
	// Upper bound & Lower bound (w. & w.o. URLs with same hash prefixes)
	// ecrimematchegsb()

	// Module 7: Read shallalist.txt and see any 2 hits in GSB hash prefixes
	// shallalisttrack()

	// Module 8: Normalize websites from Alexa top 1M and compute hash prefixes
	// alexaDataNorm()
	// alexa := readJsontoMap("alex.json")
	// gsbhashprefixes, _ := readURLFromFile("./GSBhashprefixes.txt", ^uint(0))
	// gsbhashprefixesset := make(map[string]bool)
	// for _, v := range gsbhashprefixes {
	// 	gsbhashprefixesset[v] = true
	// }
	// sitestracked := []string{}
	// for item := range alexa {
	// 	if gsbhashprefixesset[item] == true {
	// 		for cnt, ele := range alexa[item] {
	// 			sitestracked = append(sitestracked, ele)
	// 			if cnt >= 1 {
	// 				fmt.Println("hash prefix: ", item)
	// 			}
	// 		}
	// 	}
	// }
	// writeLines(sitestracked, "sitetracked.txt")

	// Module 9: Normalize URL history from Chrome and compute hash prefixes
	// browsingHistoryNorm()

	// Module 10: Collision test using suspicious GSB prefix hashes
	// collisionTest()

	// Module 11: Collision test using prefix hashes ground truth ecrime
	// collisionTest2()

	// Module 12: Browsing History prefix hash uniqueness
	// uniqueHistoryHashPrefixes()

	// Module 13: delta encoded max
	// gsbhashprefixes, _ := readURLFromFile("./GSBhashprefixes.txt", ^uint(0))
	// for i := 0; i < len(gsbhashprefixes)-1; i++ {
	// 	binary, _ := strconv.ParseUint(gsbhashprefixes[i], 16, 32)
	// 	binary2, _ := strconv.ParseUint(gsbhashprefixes[i+1], 16, 32)
	// 	diff := binary2 - binary
	// 	if diff > 65534 {
	// 		fmt.Printf("stopped\n")
	// 	}
	// }
}
