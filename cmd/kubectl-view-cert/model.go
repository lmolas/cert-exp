package main

import (
	"time"
)

// Certificate struct contains all certificate fields used for display
type Certificate struct {
	SecretName   string
	Namespace    string
	SecretKey    string
	Type         string
	Version      int
	SerialNumber string
	Issuer       string
	Validity     CertificateValidity
	Subject      string
	IsCA         bool
}

// CertificateValidity struct contains certificate date fields
type CertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func filter(datas []*Certificate, filterFunc func(*Certificate) bool) []*Certificate {
	filteredDatas := make([]*Certificate, 0)
	for _, data := range datas {
		if filterFunc(data) {
			filteredDatas = append(filteredDatas, data)
		}
	}
	return filteredDatas
}

func filterWithDate(datas []*Certificate, date time.Time, filterFunc func(*Certificate, time.Time) bool) []*Certificate {
	filteredDatas := make([]*Certificate, 0)
	for _, data := range datas {
		if filterFunc(data, date) {
			filteredDatas = append(filteredDatas, data)
		}
	}
	return filteredDatas
}

func dateAfterFilter(data *Certificate, date time.Time) bool {
	return data.Validity.NotAfter.Before(date)
}

func noCaCertFilter(data *Certificate) bool {
	return !data.IsCA
}
