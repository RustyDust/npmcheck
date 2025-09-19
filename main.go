package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/mod/semver"
)

type Affected struct {
	MinVer string
	MaxVer string
}

func main() {
	// -- get list of compromised packages
	kompromat, err := readCompromisedList()
	if err != nil {
		log.Fatalf("unable to read 'compromised.txt': %v", err)
	}

	// -- get dir to work on
	var searchBase string
	if len(os.Args) < 2 {
		searchBase = "."
	} else {
		searchBase = os.Args[1]
	}

	// -- check for existing node_modules dir
	_, err = os.Stat(fmt.Sprintf("%s/node_modules", searchBase))
	if err != nil {
		log.Fatalf("no directory 'node_modules' found in %s", searchBase)
	}

	// -- check for node_modules of directly imported modues
	out, err := exec.Command("/usr/bin/find", fmt.Sprintf("%s/node_modules/", searchBase), "-name", "node_modules").Output()
	if err != nil {
		log.Fatal(err)
	}
	if (string(out)) == "" {
		log.Printf("\n\nNo more directories found ... exiting")
		os.Exit(0)
	}

	fmt.Println()

	toCheck := strings.Split(string(out), "\n")
	checked := 0
	for _, k := range toCheck {
		if k != "" {
			checked++
			fmt.Printf("\n\nChecking modules in dir: %s\n\n", k)
			checkDir(k, kompromat)
		}
	}

	fmt.Printf("\nChecked modules in %d directories\n", checked)
}

func checkDir(checkDir string, kompromat map[string]Affected) {
	for npmmod, versions := range kompromat {
		fmt.Printf("%s: (%s/%s): ", npmmod, versions.MinVer, versions.MaxVer)
		installedVersion, err := checkNpmModule(npmmod)
		if err != nil {
			if errors.Is(errors.Unwrap(err), fs.ErrInvalid) {
				fmt.Printf("⚠️ (%v)\n", err)
				continue
			} else if errors.Is(err, fs.ErrNotExist) {
				fmt.Printf(" ✅ (not used)\n")
				continue
			} else {
				log.Fatal(err)
			}
		}

		if semCheck(installedVersion, versions.MinVer) < 0 || semCheck(installedVersion, versions.MaxVer) > 0 {
			fmt.Printf("✅ (%s not in range %s - %s)\n", installedVersion, versions.MinVer, versions.MaxVer)
		} else {
			fmt.Printf("⛔️ (%s in afftected range %s - %s)\n", installedVersion, versions.MinVer, versions.MaxVer)
		}
	}
}

func checkNpmModule(name string) (string, error) {
	checkDir := fmt.Sprintf("./node_modules/%s", name)
	checkPkg := fmt.Sprintf("%s/package.json", checkDir)

	// check if dir exists
	_, err := os.Stat(checkDir)
	if err != nil {
		return "", err
	}

	// check if file exists
	_, err = os.Stat(checkPkg)
	if err != nil {
		return "", fmt.Errorf("no package.json found: [%w]", fs.ErrInvalid)
	}

	// read package.json
	pkgjson, err := readJsonFile((checkPkg))
	if err != nil {
		return "", fmt.Errorf("error reading package.json: [%w]", fs.ErrInvalid)
	}

	if pkgver, ok := pkgjson["version"].(string); ok {
		return pkgver, nil
	}
	return "", fmt.Errorf("unable to parse package version for %s: [%w]", name, fs.ErrInvalid)
}

func readCompromisedList() (map[string]Affected, error) {
	file, err := os.ReadFile("compromised.txt")
	if err != nil {
		log.Fatal(err) // no sense to continue here
	}
	split := strings.Split(string(file), "\n")

	returnArray := make(map[string]Affected)
	for _, v := range split {
		name, version, err := splitPackage(v)
		if err != nil {
			return nil, err
		}

		// check if we already have a element with name "name"
		if current, ok := returnArray[name]; ok {
			// fmt.Printf("Min:%t Max:%t Ver:%t\n", semver.IsValid(current.MinVer), semver.IsValid(current.MaxVer), semver.IsValid(version))
			// fmt.Printf("Checking %v against %v (%d/%d)\n", current, version, semCheck(current.MaxVer, version), semCheck(current.MaxVer, version))
			changed := false
			if semCheck(current.MinVer, version) > 0 {
				current.MinVer = version
				changed = true
			}
			if semCheck(current.MaxVer, version) < 0 {
				current.MaxVer = version
				changed = true
			}
			if changed {
				// fmt.Printf("Updating '%s' with %v\n", name, current)
				returnArray[name] = current
			}
		} else {
			returnArray[name] = Affected{
				MinVer: version,
				MaxVer: version,
			}
		}
	}
	return returnArray, nil
}

func semCheck(value, compare string) int {
	return semver.Compare(fmt.Sprintf("v%s", value), fmt.Sprintf("v%s", compare))
}
func splitPackage(toSplit string) (string, string, error) {
	if atat := strings.Index(toSplit[1:], "@"); atat > 0 {
		name := toSplit[:atat+1]
		version := toSplit[atat+2:]
		// fmt.Printf("Package: %32s, Version: %16s\n", name, version)
		return name, version, nil
	}
	return "", "", errors.New("WTF")
}

func readJsonFile(fileToRead string) (map[string]any, error) {
	fileContent, err := os.ReadFile(fileToRead)
	if err != nil {
		return nil, err
	}

	var jsonData map[string]any
	err = json.Unmarshal(fileContent, &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}
