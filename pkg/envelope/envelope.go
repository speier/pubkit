package envelope

type Recipient struct {
	PubKey  string
	EPubKey string
	DocKey  []byte
}

type Envelope struct {
	Recipients []*Recipient
	Body       []byte
}
