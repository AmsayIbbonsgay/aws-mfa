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

var tokenDuration int64 = 43200

func main() {

	// awsCredentialFilePath := usr.HomeDir + "/.aws/credentials" // TODO, unfuck somehow
	// awsConfigFilePath := usr.HomeDir + "/.aws/config"

	awsCredentialFilePath, awsConfigFilePath := getAWSFilePaths()

	// ex, err := os.Executable()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// exPath := filepath.Dir(ex)
	// awsCredentialFilePath := exPath + "/credentials"
	// outawsCredentialFilePath := exPath + "/credentials-out" // for debug, TODO remove
	// awsCredentialFilePath := exPath + "/credentials-in-place"
	// outawsCredentialFilePath := exPath + "/credentials-in-place" // for debug, TODO remove

	fmt.Println(awsCredentialFilePath)

	// awsConfigFilePath := exPath + "/config"  TODO

	awsCredINI, err := ini.Load(awsCredentialFilePath)
	if err != nil {
		log.Fatal(fmt.Errorf("error opening credentials file: %v", err))
	}

	awsConfigINI, err := ini.Load(awsConfigFilePath)
	if err != nil {
		log.Fatal(fmt.Errorf("error opening credentials file: %v", err))
	}

	// check that args given make sense,
	profile, mfaCode, mfaDevice := getArgs(awsCredINI) // TODO, use a struct instead of this.
	// TODO, validate the config file also - is there a config file entry?

	mfaProfileExists := checkMFAProfileExists(profile, awsCredINI)

	// validate mfaCode
	validateMFACode(mfaCode)
	if err != nil {
		log.Fatal(err)
	}

	if mfaProfileExists == true {
		// if the mfaProfileExists, assume that we've been here before, and it is source creds.

		tempCreds := getTempCredentials(mfaDevice, mfaCode, awsCredentialFilePath, "mfa-"+profile)

		writeCredentialsToSection(awsCredINI.Section(profile), tempCreds)

		awsCredINI.SaveTo(awsCredentialFilePath)

		fmt.Printf("\nSuccessfully used \"%v\" profile to create temp mfa credentials at \"%v\" profile", "mfa-"+profile, profile)
		fmt.Println("output file:" + awsCredentialFilePath)

	} else {
		// if profile hasn't been done before
		// 	copy source profile to mfa-${source}

		newSourceProfileName := "mfa-" + profile

		for _, INIfile := range []*ini.File{awsCredINI, awsConfigINI} {
			newSourceProfileSection, err := INIfile.NewSection(newSourceProfileName)

			oldSourceProfileSection := INIfile.Section(profile)

			if err != nil {
				log.Fatal("ERROR creating new profile section:", err)
			}

			err = copyINISection(oldSourceProfileSection, newSourceProfileSection)

			if err != nil {
				log.Fatal("ERROR copying source profile credentials to dest: ", err)
			}

			//	overwrite source profile with target credentials
			tempCreds := getTempCredentials(mfaDevice, mfaCode, awsCredentialFilePath, profile)
			writeCredentialsToSection(oldSourceProfileSection, tempCreds)
			INIfile.SaveTo(awsCredentialFilePath) // todo you're dumb
		}

		fmt.Printf("\nSuccessfully copied \"%v\" profile to \"%v\" profile, and saved temp mfa credentials to \"%v\" profile\n", profile, newSourceProfileName, profile)
		fmt.Println("output file:" + awsCredentialFilePath)
	}
}

func getTempCredentials(mfaDevice string, mfaCode string, awsCredentialFilePath string, profile string) *sts.Credentials {

	stsClient := sts.New(session.Must(session.NewSession(&aws.Config{
		Credentials: credentials.NewSharedCredentials(awsCredentialFilePath, profile),
	})))

	tokenRequest := sts.GetSessionTokenInput{
		DurationSeconds: &tokenDuration,
		SerialNumber:    &mfaDevice,
		TokenCode:       &mfaCode,
	}

	output, err := stsClient.GetSessionToken(&tokenRequest)

	if err != nil {
		log.Fatal(err)
	}

	return output.Credentials
}

func getAWSFilePaths() (awsCredentialFilePath string, awsConfigFilePath string) {

	homeDir, err := os.UserHomeDir()

	if err != nil {
		log.Fatal("Error finding user homedir: ", err)
	}

	return homeDir + "/.aws/credentials", homeDir + "/.aws/config"

}

func writeCredentialsToSection(section *ini.Section, creds *sts.Credentials) {

	section.Key("aws_access_key_id").SetValue(*creds.AccessKeyId)
	section.Key("aws_secret_access_key").SetValue(*creds.SecretAccessKey)
	section.Key("aws_session_token").SetValue(*creds.SessionToken)
}

func checkMFAProfileExists(profile string, iniFile *ini.File) bool {
	if stringInSlice("mfa-"+profile, iniFile.SectionStrings()) == true {
		return true
	}
	fmt.Println("mfa profile does not exist, attempting to create")
	return false
}

//
func getArgs(awsCredINI *ini.File) (profile string, mfaCode string, mfaDevice string) {
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
		profile := getDefaultProfile(awsCredINI)

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

func getDefaultProfile(awsCredINI *ini.File) string {

	defaultProfilesOrder := []string{"default", "mfa-default"}

	// if mfa-default profile exists and is valid, use that one

	for _, v := range defaultProfilesOrder {

		// works because only err possible is "section does not exist"
		profileSection, err := awsCredINI.GetSection(v)
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
