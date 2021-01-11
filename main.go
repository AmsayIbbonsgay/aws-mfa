package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/ini.v1"
)

const mfaConfig = "/mfa-cfg.csv" // todo, change to be variable

func main() {

	// AWSCredentialFilePath := usr.HomeDir + "/.aws/credentials" // TODO, unfuck somehow
	// AWSConfigFilePath := usr.HomeDir + "/.aws/config"

	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exPath := filepath.Dir(ex)
	// AWSCredentialFilePath := exPath + "/credentials"
	// outAWSCredentialFilePath := exPath + "/credentials-out" // for debug, TODO remove
	AWSCredentialFilePath := exPath + "/credentials-in-place"
	outAWSCredentialFilePath := exPath + "/credentials-in-place" // for debug, TODO remove

	fmt.Println(AWSCredentialFilePath)

	// AWSConfigFilePath := exPath + "/config"  TODO

	credConfig, err := ini.Load(AWSCredentialFilePath)
	if err != nil {
		log.Fatal(fmt.Errorf("error opening credentials file: %v", err))
	}

	// check that args given make sense,
	profile, mfaCode, mfaDevice := getArgs(credConfig) // TODO, use a struct instead of this.

	mfaProfileExists := checkMFAProfileExists(profile, credConfig)

	// validate mfaCode
	validateMFACode(mfaCode)
	if err != nil {
		log.Fatal(err)
	}

	// get temp creds from STS
	stsClient := sts.New(session.Must(session.NewSession(&aws.Config{
		Credentials: getCredentials(mfaProfileExists, AWSCredentialFilePath, profile),
	})))

	var tokenDuration int64 = 43200

	tokenRequest := sts.GetSessionTokenInput{
		DurationSeconds: &tokenDuration,
		SerialNumber:    &mfaDevice,
		TokenCode:       &mfaCode,
	}

	output, err := stsClient.GetSessionToken(&tokenRequest)

	if err != nil {
		log.Fatal(err)
	}

	// if the profile name starts with mfa, inform user that they've messed up. TODO, move whole thing to getArgs()

	// matched, err := regexp.Match(`^mfa-*`, []byte(profile))

	// if err != nil {
	// 	log.Fatal(err)
	// }

	if mfaProfileExists == true {
		// if the mfaProfileExists, assume that we've been here before, and it is source creds.

		writeCredentialsToSection(credConfig.Section(profile), output.Credentials)

		credConfig.SaveTo(outAWSCredentialFilePath)

		fmt.Printf("\nSuccessfully used \"%v\" profile to create temp mfa credentials at \"%v\" profile", "mfa-"+profile, profile)
		fmt.Println("output file:" + outAWSCredentialFilePath)

	} else {
		// if profile hasn't been done before
		// 	copy source profile to mfa-${source}

		newSourceProfileName := "mfa-" + profile
		newSourceProfileSection, err := credConfig.NewSection(newSourceProfileName)

		oldSourceProfileSection := credConfig.Section(profile)

		if err != nil {
			log.Fatal("ERROR creating new profile section:", err)
		}

		err = copyINISection(oldSourceProfileSection, newSourceProfileSection)

		if err != nil {
			log.Fatal("ERROR copying source profile credentials to dest: ", err)
		}

		//	overwrite source profile with target credentials

		writeCredentialsToSection(oldSourceProfileSection, output.Credentials)

		credConfig.SaveTo(outAWSCredentialFilePath)
		fmt.Printf("\nSuccessfully copied \"%v\" profile to \"%v\" profile, and saved temp mfa credentials to \"%v\" profile", profile, newSourceProfileName, profile)
		fmt.Println("output file:" + outAWSCredentialFilePath)
	}

}

func writeCredentialsToSection(section *ini.Section, creds *sts.Credentials) {

	section.Key("aws_access_key_id").SetValue(*creds.AccessKeyId)
	section.Key("aws_secret_access_key").SetValue(*creds.SecretAccessKey)
	section.Key("aws_session_token").SetValue(*creds.SessionToken)
}

func getCredentials(mfaProfileExists bool, AWSCredentialFilePath string, profile string) *credentials.Credentials {
	if mfaProfileExists == true {
		fmt.Printf("getting creds for profile \"%v\" from file %v\n", "mfa-"+profile, AWSCredentialFilePath)
		return credentials.NewSharedCredentials(AWSCredentialFilePath, "mfa-"+profile)
	} else {
		fmt.Printf("getting creds for profile %v from file %v\n", profile, AWSCredentialFilePath)
		return credentials.NewSharedCredentials(AWSCredentialFilePath, profile)
	}
}

func checkMFAProfileExists(profile string, credConfig *ini.File) bool {
	if stringInSlice("mfa-"+profile, credConfig.SectionStrings()) == true {
		fmt.Println("mfa profile exists")
		return true
	}
	fmt.Println("mfa profile does not exist")
	return false
}

//
func getArgs(credConfig *ini.File) (profile string, mfaCode string, mfaDevice string) {
	flag.Parse()
	args := flag.Args()

	usageString := `Usage: mfa [profile] <mfa-code>
where <mfa-code> is a 6 digit mfa code, likely from your mobile device or 1password`

	//TODO, replace this with a switch statement for chrissakes

	// no args given, assume naive run
	if len(args) == 0 {
		fmt.Println(usageString)
		os.Exit(0)
	}

	// more than two, assume some mess up, scream
	if len(args) > 2 {
		log.Fatal("Script can not take more than 2 args: " + usageString)
	}

	// 1 arg, assume default profile
	if len(args) == 1 {
		fmt.Println("No profile given, using default profiles")
		profile := getDefaultProfile(credConfig)

		return profile, args[0], getMFADevice(profile)
	}

	// profile name manually selected
	return args[0], args[1], getMFADevice(profile)
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func copyINISection(sourceSection *ini.Section, targetSection *ini.Section) error {
	for k, v := range sourceSection.KeysHash() {
		_, err := targetSection.NewKey(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func getDefaultProfile(credConfig *ini.File) string {

	defaultProfilesOrder := []string{"default", "mfa-default"}

	// if mfa-default profile exists and is valid, use that one

	for _, v := range defaultProfilesOrder {

		// works because only err possible is "section does not exist"
		profileSection, err := credConfig.GetSection(v)
		if err != nil {
			fmt.Printf("default profile %v does not exist in credentials file \n", v)
			continue
		}

		err = validateProfileSection(profileSection)

		if err != nil {
			fmt.Printf("default profile \"%v\" failed validation: %v \n", v, err)
			continue
		}

		fmt.Printf("Using profile: \"%v\" \n", v)
		return v

	}

	fmt.Println("No profile given, and no valid default profiles exist. Acceptable default profiles: ", defaultProfilesOrder)
	os.Exit(1)
	return "" // dummy for happy compiler
}

// Given a section, validates that it has the correct keys, and values match regex. Returns nil if a-ok
func validateProfileSection(profileSection *ini.Section) error {

	requiredFields := []string{"aws_access_key_id", "aws_secret_access_key"}

	for _, v := range requiredFields {
		keyExists := profileSection.HasKey(v)

		if keyExists != true {
			return fmt.Errorf("Error validating profile field: \"%v\", field does not exist", v)
		}
	}

	return nil
}
func validateMFACode(mfaCode string) error {
	matched, err := regexp.Match(`^[0-9]{6}$`, []byte(mfaCode))

	if err != nil {
		return fmt.Errorf("Error validating MFA code: %v", err)
	}

	if matched != true {
		return fmt.Errorf("mfa code needs to be 6 numbers")
	}

	return nil
}

func getMFADevice(profile string) string {

	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exPath := filepath.Dir(ex)

	configFile := exPath + mfaConfig

	f, err := os.Open(configFile)

	if err != nil {
		log.Fatal(err)
	}

	fileReader := bufio.NewReader(f)
	r := csv.NewReader(fileReader)
	r.Comma = '='

	records, err := r.ReadAll()

	for _, v := range records {
		if v[0] == profile {
			return v[1]
		}
	}

	log.Fatal(fmt.Sprintf("profile %v not found in mfa config file %v ", profile, configFile))
	return "" // for make compiler happy
}

// take in one optional arg (profile), and one required arg (mfa code)

// find the location of the aws config and credentials files

// read the INI format of these files

// func handleFatalError(prefix string, err error) {
// 	if err != nil {
// 		fmt.Println(prefix, err)
// 		os.Exit(1)   TODO
// 	}
// }
