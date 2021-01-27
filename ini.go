package main

import (
	"fmt"
	"log"

	"gopkg.in/ini.v1"
)

func getIniFile(filePath string) iniFile {
	iniobj, err := ini.Load(filePath)
	if err != nil {
		log.Fatal(fmt.Errorf("error opening credentials file: %v", err))
	}

	return iniFile{
		path: filePath,
		file: iniobj,
	}
}

type iniFile struct {
	path string
	file *ini.File
}

func (i iniFile) save() {
	err := i.file.SaveTo(i.path)
	if err != nil {
		log.Fatal("ERROR saving file: ", i.path, err)
	}
}

func (i iniFile) copyINISection(sourceSectionName string, targetSectionName string) error {
	sourceSection := i.file.Section(sourceSectionName)
	targetSection := i.file.Section(targetSectionName)
	for k, v := range sourceSection.KeysHash() {
		_, err := targetSection.NewKey(k, v)
		if err != nil {
			return err
		}
	}
	return nil
}
