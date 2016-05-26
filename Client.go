package ssftp

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"

	ssh "golang.org/x/crypto/ssh"

	sftp "github.com/pkg/sftp"
)

// SFTPClient interface for sftp clients.
type SFTPClient interface {
	ReadFolder() ([]os.FileInfo, error)
	ReadFile() ([]os.FileInfo, error)
	WriteFile(d string, p interface{}) ([]os.FileInfo, error)
}

// Client is a basic SFTP client, inheriting from sftp.Client.
// Allows us to interact with sftp without faffing about.
type Client struct {
	Client *sftp.Client
}

// NewClientWithKey returns a new STPClient for the given hostname, user and key.
func NewClientWithKey(host, user, keyPath string) (*Client, error) {
	key, _ := parseKeyFromPath(keyPath)
	auth := ssh.PublicKeys(key)
	return newClient(host, user, auth)
}

// NewClientWithCredentials returns a new Client given the hostname and credentials.
func NewClientWithCredentials(host, user, pass string) (*Client, error) {
	if pass == "" {
		return nil, fmt.Errorf("can't create SFTP client with empty password")
	}
	auth := ssh.Password(pass)
	return newClient(host, user, auth)
}

func newClient(host string, user string, auth ssh.AuthMethod) (*Client, error) {
	clientConfig := buildClientConfig(auth, user)
	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		panic(err.Error())
	}
	msftp, err := sftp.NewClient(client)
	if err != nil {
		panic(err.Error())
	}
	cl := &Client{Client: msftp}
	return cl, nil
}

// WriteXMLFile writes XML to the given file path.
func (s *Client) WriteXMLFile(filePath string, data interface{}) error {
	xml, err := xml.MarshalIndent(data, "  ", "    ")
	if err != nil {
		return fmt.Errorf("can't marshall XML for SFTP file: %v", err)
	}
	return s.WriteFile(filePath, xml)
}

// WriteFile writes arbitrary bytes to the given file path.
func (s *Client) WriteFile(filePath string, content []byte) error {
	f, err := s.Client.Create(filePath)
	if err != nil {
		return fmt.Errorf("can't create file at path '%s': %v", filePath, err)
	}

	_, err = f.Write(content)
	if err != nil {
		return fmt.Errorf("can't create file at path '%s': %v", filePath, err)
	}

	return nil
}

func parseKeyFromPath(p string) (key ssh.Signer, err error) {
	usr, _ := user.Current()
	file := usr.HomeDir + p
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	key, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return
	}
	return
}

func buildClientConfig(a ssh.AuthMethod, u string) *ssh.ClientConfig {
	Cconfig := &ssh.ClientConfig{
		User: u,
		Auth: []ssh.AuthMethod{a},
	}
	return Cconfig
}
