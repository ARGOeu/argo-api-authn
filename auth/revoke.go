package auth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/ARGOeu/argo-api-authn/utils"
	LOGGER "github.com/sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// CRLCheckRevokedCert checks whether or not a certificate has been revoked
func CRLCheckRevokedCert(cert *x509.Certificate) error {

	var err error
	var goMaxP, psi, csi int
	var crtList *pkix.TBSCertificateList
	var errChan = make(chan error)
	var doneChan = make(chan bool, 1)

	defer close(doneChan)

	var wg = new(sync.WaitGroup)

	totalTime := time.Now()

	if len(cert.CRLDistributionPoints) == 0 {
		err := &utils.APIError{Code: 403, Message: "Your certificate is invalid. No CRLDistributionPoints found on the certificate", Status: "ACCESS_FORBIDDEN"}
		return err
	}

	for _, crlURL := range cert.CRLDistributionPoints {

		wg.Add(1)
		go func(doneChan <-chan bool, errChan chan<- error, wg *sync.WaitGroup, crlURL string) {

			defer wg.Done()

			// count how much time it takes to fetch a crl
			t1 := time.Now()
			// grab the crl
			if crtList, err = FetchCRL(crlURL); err != nil {
				errChan <- err
			}
			LOGGER.Infof("PERFORMANCE    Request to CRL: %v took %v", crlURL, time.Since(t1))

			// how many chunks should the slice should be split into
			goMaxP = 2
			// representing the current index where we going to slice the revoked certificate list
			csi = 0
			// representing the previous index where we sliced the revoked certificate list
			psi = 0

			rvkCrtListLen := len(crtList.RevokedCertificates)
			LOGGER.Infof("PERFORMANCE    Request to CRL: %v returned %v elements", crlURL, rvkCrtListLen)

			// distribute the list of revoked certs evenly
			// in order to break up the slice to a specified number of chunks
			// in each iteration we move our current slicing index (csi), from the previous slicing index(psi) another n number of positions
			// where n is the amount of slice elements that can be retrieved by using the specified denominator
			// if the remaining elements can't be evenly distributed to at least 2 chunks, then we collect them all together into one
			// e.g [0,1,2,4,5,6,7,8,9] and chunks = 3
			// 1: [0,1,2], 2:[3,4,5] 3:[6,7,8,9]
			for j := 1; j <= goMaxP; j++ {

				csi = psi + rvkCrtListLen/goMaxP
				if len(crtList.RevokedCertificates[psi:])/goMaxP < 2 {
					wg.Add(1)
					go SynchronizedCheckInCRL(doneChan, errChan, crtList.RevokedCertificates[psi:], cert.SerialNumber, wg)
					break
				}
				wg.Add(1)
				go SynchronizedCheckInCRL(doneChan, errChan, crtList.RevokedCertificates[psi:csi], cert.SerialNumber, wg)
				psi = csi
			}
		}(doneChan, errChan, wg, crlURL)
	}

	// cancel mechanism
	go func() {
		wg.Wait()
		LOGGER.Infof("PERFORMANCE    Total time for examining certificate revocation %v", time.Since(totalTime))
		close(errChan)
	}()

	// listen on the err channel until an error has occurred or no more goroutines are sending
	for tmp := range errChan {
		if tmp != nil {
			err = tmp
			doneChan <- true
		}
	}

	LOGGER.Infof("PERFORMANCE    Total time for examining certificate revocation %v", time.Since(totalTime))
	return err
}

// CheckInCRL checks if a serial number exists within the serial numbers of other revoked certificates
func SynchronizedCheckInCRL(doneChan <-chan bool, errChan chan<- error, revokedCerts []pkix.RevokedCertificate, serialNumber *big.Int, wg *sync.WaitGroup) {

loop:
	for _, cert := range revokedCerts {
		select {
		case <-doneChan:
			break loop
		case errChan <- nil:
			if serialNumber.Cmp(cert.SerialNumber) == 0 {
				err := &utils.APIError{Code: 403, Message: "Your certificate has been revoked", Status: "ACCESS_FORBIDDEN"}
				errChan <- err
				break loop
			}
		}
	}
	defer wg.Done()
}

// FetchCRL fetches the CRL
func FetchCRL(url string) (*pkix.TBSCertificateList, error) {

	var err error
	var crtList *pkix.CertificateList
	var resp *http.Response
	var crlBytes []byte

	// initialize the client and perform a get request to grab the crl
	client := &http.Client{Timeout: time.Duration(60 * time.Second)}
	if resp, err = client.Get(url); err != nil {
		return &crtList.TBSCertList, err
	}

	// read the response
	if crlBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		return &crtList.TBSCertList, err
	}

	defer resp.Body.Close()

	// create the crl from the byte slice
	if crtList, err = x509.ParseCRL(crlBytes); err != nil {
		return &crtList.TBSCertList, err
	}

	return &crtList.TBSCertList, err
}
