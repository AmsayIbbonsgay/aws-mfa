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

const mfaConfig = "/mfa-cfg.csv"

var tokenDuration int64 = 43200

func main() {

	awsCredentialFilePath, awsConfigFilePath := getAWSFilePaths()

	awsCredINI := getIniFile(awsCredentialFilePath)
	awsConfigINI := getIniFile(awsConfigFilePath)

	// check that args given make sense,
	profile, mfaCode, mfaDevice := getArgs(awsCredINI.file)

	mfaProfileExists := checkMFAProfileExists(profile, awsCredINI.file)

	validateMFACode(mfaCode)

	if mfaProfileExists == true {
		// if the mfaProfileExists, assume that we've been here before, and it is source creds.

		tempCreds := getTempCredentials(mfaDevice, mfaCode, awsCredentialFilePath, "mfa-"+profile)

		writeCredentialsToSection(awsCredINI.file.Section(profile), tempCreds)

		awsCredINI.save()

		fmt.Printf("\nSuccessfully used \"%v\" profile to create temp mfa credentials at \"%v\" profile\n", "mfa-"+profile, profile)
		fmt.Println("output file:" + awsCredINI.path)

	} else {
		// if profile hasn't been done before
		// 	copy source profile to mfa-${source}
		// I also do this for the config file, in case it needs to be operational

		// credential file
		oldCredProfileSection := awsCredINI.file.Section(profile)

		err := awsCredINI.copyINISection(profile, "mfa-"+profile)

		if err != nil {
			log.Fatal("ERROR copying credential sections:", err)
		}

		tempCreds := getTempCredentials(mfaDevice, mfaCode, awsCredINI.path, profile)
		writeCredentialsToSection(oldCredProfileSection, tempCreds) // todo, fix uo?

		awsCredINI.save()

		// config file
		err = awsConfigINI.copyINISection(profile, "mfa-"+profile)

		if err != nil {
			log.Fatal("ERROR copying config sections: ", err) // todo
		}

		awsConfigINI.save()
		fmt.Printf("\nSuccessfully copied \"%v\" profile to \"%v\" profile, and saved temp mfa credentials to \"%v\" profile\n", profile, "mfa-"+profile, profile)
		fmt.Println("output file:" + awsCredINI.path)
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
where <mfa-code> is a 6 digit mfa code, likely from your authenticator app,  password manager, or hardware authentication device`

	argNum := len(args)
	switch {
	// no args given, assume naive run
	case argNum == 0:
		fmt.Println(usageString)
		os.Exit(0)
	// more than two, assume some mess up, scream
	case argNum > 2:
		log.Fatal("Script can not take more than 2 args: " + usageString)
	// 1 arg, assume default profile
	case argNum == 1:
		fmt.Println("No profile given, using default profiles")
		profile := getDefaultProfile(awsCredINI)

		return profile, args[0], getMFADevice(profile)
	// 2 args, profile name manually selected
	default:
		return args[0], args[1], getMFADevice(profile)
	}
	return "", "", ""
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
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

// Given a section, validates that it has the correct keys, returns nil if a-ok
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

func getMFAConfigFilePath() string {

	// if AWS_MFA_CONFIG_FILE set, use that
	val, present := os.LookupEnv("AWS_MFA_CONFIG_FILE")

	if present {
		return val
	}

	// next, check in the same dir as the executable
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exPath := filepath.Dir(ex)

	localfile := exPath + mfaConfig
	if _, err := os.Stat(localfile); err == nil {
		return localfile
	}

	// finally, check in ~/.aws/mfa-cfg.csv
	homeDir, err := os.UserHomeDir()

	if err != nil {
		log.Fatal("Error finding user homedir: ", err)
	}

	return homeDir + "/.aws" + mfaConfig
}

func getMFADevice(profile string) string {

	configFilePath := getMFAConfigFilePath()
	f, err := os.Open(configFilePath)

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

	log.Fatal(fmt.Sprintf("profile %v not found in mfa config file %v ", profile, configFilePath))
	return "" // for make compiler happy
}
